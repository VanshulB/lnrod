use std::{cmp, env};
use std::collections::HashMap;
use std::fs;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{self, *};

use anyhow::Result;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{BlockHash, Network};
use lightning::chain;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::keysinterface::KeysInterface;
use lightning::chain::Watch;
use lightning::ln::msgs::NetAddress;
use lightning::ln::channelmanager::{
	ChainParameters, ChannelManagerReadArgs, MIN_FINAL_CLTV_EXPIRY,
};
use lightning::ln::peer_handler::MessageHandler;
use lightning::ln::{channelmanager, PaymentHash, PaymentPreimage};
use lightning::routing::network_graph::{NetGraphMsgHandler, RoutingFees};
use lightning::util::events::{EventHandler, Event};
use lightning::util::ser::{ReadableArgs};
use lightning::chain::BestBlock;
use lightning::routing::router::RouteHintHop;
use lightning::routing::network_graph::NetworkGraph;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};
use lightning::routing::router::RouteHint;
use lightning_background_processor::BackgroundProcessor;
use lightning_signer::lightning;
use lightning_block_sync::{init, poll, SpvClient, UnboundedCache};
use lightning_invoice::{Invoice, payment};
use lightning_invoice::payment::PaymentError;
use lightning_invoice::utils::DefaultRouter;
use lightning_persister::FilesystemPersister;
use lightning_signer::lightning::chain::keysinterface::Recipient;
use rand::{Rng, thread_rng};
use tokio::runtime;
use tokio::runtime::Handle;

use crate::lightning_invoice;
use crate::bitcoind_client::BitcoindClient;
use crate::config::Config;
use crate::convert::BlockchainInfo;
use crate::fslogger::FilesystemLogger;
use crate::logadapter::LoggerAdapter;
use crate::signer::get_keys_manager;
use crate::signer::keys::DynKeysInterface;
use crate::{disk, handle_ldk_events, ArcChainMonitor, ChannelManager, HTLCDirection, HTLCStatus, MilliSatoshiAmount, PaymentInfoStorage, PeerManager, IgnoringMessageHandler, Sha256};
use crate::disk::HostAndPort;
use crate::net::Connector;
use crate::tor::TorManager;

#[derive(Clone)]
pub struct NodeBuildArgs {
	pub bitcoind_rpc_username: String,
	pub bitcoind_rpc_password: String,
	pub bitcoind_rpc_host: String,
	pub bitcoind_rpc_port: u16,
	pub storage_dir_path: String,
	pub peer_listening_port: u16,
	pub network: Network,
	pub disk_log_level: log::LevelFilter,
	pub console_log_level: log::LevelFilter,
	pub signer_name: String,
	/// Whether to turn on Tor support
	pub tor: bool,
	/// p2p announcement name for this node
	pub name: Option<String>,
	pub config: Config,
	pub vls_port: u16,
}

type Router = DefaultRouter<Arc<NetworkGraph>, Arc<LoggerAdapter>>;

pub struct MyEventHandler {
	handle: Handle,
	channel_manager: Arc<ChannelManager>,
	chain_monitor: Arc<ArcChainMonitor>,
	bitcoind_client: Arc<BitcoindClient>,
	keys_manager: Arc<DynKeysInterface>,
	payment_storage: PaymentInfoStorage,
	network: Network,
}

impl EventHandler for MyEventHandler {
	fn handle_event(&self, event: &Event) {
		self.handle.block_on(
			handle_ldk_events(
				self.channel_manager.clone(),
				self.chain_monitor.clone(),
				self.bitcoind_client.clone(),
				self.keys_manager.clone(),
				self.payment_storage.clone(),
				self.network,
				event.clone(),
			)
		)
	}
}

pub(crate) type InvoicePayer = payment::InvoicePayer<
	Arc<ChannelManager>,
	Router,
	Arc<Mutex<ProbabilisticScorer<Arc<NetworkGraph>>>>,
	Arc<LoggerAdapter>,
	MyEventHandler,
>;

#[allow(dead_code)]
pub(crate) struct Node {
	pub(crate) peer_manager: Arc<PeerManager>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) payer: Arc<InvoicePayer>,
	pub(crate) payment_info: PaymentInfoStorage,
	pub(crate) keys_manager: Arc<DynKeysInterface>,
	pub(crate) ldk_data_dir: String,
	pub(crate) bitcoind_client: Arc<BitcoindClient>,
	pub(crate) network: Network,
	pub(crate) background_processor: BackgroundProcessor,
	pub(crate) chain_monitor: Arc<ArcChainMonitor>,
	pub(crate) connector: Arc<Connector>,
	p2p_runtime: runtime::Runtime,
}

pub(crate) struct NetworkController {
	#[allow(unused)]
	tor: Option<TorManager>
}

pub(crate) async fn build_node(args: NodeBuildArgs) -> (Node, NetworkController) {
	// Initialize the LDK data directory if necessary.
	let ldk_data_dir = args.storage_dir_path.clone();
	fs::create_dir_all(ldk_data_dir.clone()).unwrap();

	// Initialize the Logger
	// TODO(ksedgwic) - Resolve data_dir setup and move this to main_server because earlier.
	let is_daemon = false;
	let console_log_level = if is_daemon { log::LevelFilter::Off } else { args.console_log_level };
	log::set_boxed_logger(Box::new(FilesystemLogger::new(
		ldk_data_dir.clone(),
		args.disk_log_level,
		console_log_level,
	)))
		.unwrap_or_else(|e| panic!("Failed to create FilesystemLogger: {}", e));
	log::set_max_level(cmp::max(args.disk_log_level, console_log_level));

	// Initialize our bitcoind client.
	let (user, pass) =
		if args.bitcoind_rpc_username.is_empty() {
			// try to get from cookie file
			bitcoin_rpc_cookie(args.network)
		} else {
			(args.bitcoind_rpc_username.clone(), args.bitcoind_rpc_password.clone())
		};
	let bitcoind_client = BitcoindClient::new(
		args.bitcoind_rpc_host.clone(),
		args.bitcoind_rpc_port,
		user,
		pass,
	)
		.await
		.unwrap_or_else(|e| panic!("Failed to connect to bitcoind client: {}", e));

	let bitcoind_client_arc = Arc::new(bitcoind_client.clone());

	// Initialize the KeysManager

	let manager =
		get_keys_manager(args.signer_name.as_str(), args.vls_port, args.network, ldk_data_dir.clone(), bitcoind_client.clone()).await.unwrap();
	let keys_manager = Arc::new(DynKeysInterface::new(manager));

	build_with_signer(keys_manager, args, ldk_data_dir, bitcoind_client_arc).await
}

fn bitcoin_network_path(base_path: PathBuf, network: Network) -> PathBuf {
	match network {
		Network::Bitcoin => base_path,
		Network::Testnet => base_path.join("testnet3"),
		Network::Signet => base_path.join("signet"),
		Network::Regtest => base_path.join("regtest"),
	}
}

fn bitcoin_rpc_cookie(network: Network) -> (String, String) {
	let home = env::var("HOME").expect("cannot get cookie file if HOME is not set");
	let bitcoin_path = Path::new(&home).join(".bitcoin");
	let bitcoin_net_path = bitcoin_network_path(bitcoin_path, network);
	let cookie_path = bitcoin_net_path.join("cookie");
	info!("auth to bitcoind via cookie {}", cookie_path.to_string_lossy());
	let cookie_contents = read_to_string(cookie_path).expect("cookie file read");
	let mut iter = cookie_contents.splitn(2, ":");
	(iter.next().expect("cookie user").to_string(), iter.next().expect("cookie pass").to_string())
}

async fn build_with_signer(
	keys_manager: Arc<DynKeysInterface>,
	args: NodeBuildArgs,
	ldk_data_dir: String,
	bitcoind_client_arc: Arc<BitcoindClient>,
) -> (Node, NetworkController) {
	let mut bitcoind_client = (*bitcoind_client_arc).clone();

	// ## Setup
	// Step 1: Initialize the FeeEstimator

	// BitcoindClient implements the FeeEstimator trait, so it'll act as our fee estimator.
	let fee_estimator = Arc::clone(&bitcoind_client_arc);

	let logadapter = Arc::new(LoggerAdapter::new());

	// Step 3: Initialize the BroadcasterInterface

	// BitcoindClient implements the BroadcasterInterface trait, so it'll act as our transaction
	// broadcaster.
	let broadcaster = Arc::clone(&bitcoind_client_arc);

	// Step 4: Initialize Persist
	let persister = Arc::new(FilesystemPersister::new(ldk_data_dir.clone()));

	// Step 5: Initialize the ChainMonitor
	let chain_monitor: Arc<ArcChainMonitor> = Arc::new(ChainMonitor::new(
		None,
		broadcaster.clone(),
		logadapter.clone(),
		fee_estimator.clone(),
		persister.clone(),
	));

	// Step 7: Read ChannelMonitor state from disk
	let monitors_path = format!("{}/monitors", ldk_data_dir.clone());
	let mut outpoint_to_channelmonitor =
		disk::read_channelmonitors(monitors_path.to_string(), keys_manager.clone()).unwrap();

	// Step 8: ... profit

	// Step 9: Initialize the ChannelManager
	let user_config = args.config.bitcoin_channel().into();

	let mut restarting_node = true;
	let (channel_manager_blockhash, channel_manager) = {
		if let Ok(mut f) = fs::File::open(format!("{}/manager", ldk_data_dir.clone())) {
			let mut channel_monitor_mut_references = Vec::new();
			for (_, channel_monitor) in outpoint_to_channelmonitor.iter_mut() {
				channel_monitor_mut_references.push(&mut channel_monitor.1);
			}
			let read_args = ChannelManagerReadArgs::new(
				keys_manager.clone(),
				fee_estimator.clone(),
				chain_monitor.clone(),
				broadcaster.clone(),
				logadapter.clone(),
				user_config,
				channel_monitor_mut_references,
			);
			<(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
		} else {
			// We're starting a fresh node.
			restarting_node = false;
			let getinfo_resp = bitcoind_client.get_blockchain_info().await;
			let best_block =
				BestBlock::new(getinfo_resp.latest_blockhash, getinfo_resp.latest_height as u32);
			let chain_params = ChainParameters { network: args.network, best_block };
			let fresh_channel_manager = channelmanager::ChannelManager::new(
				fee_estimator.clone(),
				chain_monitor.clone(),
				broadcaster.clone(),
				logadapter.clone(),
				keys_manager.clone(),
				user_config,
				chain_params,
			);
			(getinfo_resp.latest_blockhash, fresh_channel_manager)
		}
	};

	// Step 10: Sync ChannelMonitors and ChannelManager to chain tip
	let mut chain_listener_channel_monitors = Vec::new();
	let mut cache = UnboundedCache::new();
	let mut chain_tip: Option<poll::ValidatedBlockHeader> = None;
	if restarting_node {
		let mut chain_listeners =
			vec![(channel_manager_blockhash, &channel_manager as &dyn chain::Listen)];

		for (outpoint, blockhash_and_monitor) in outpoint_to_channelmonitor.drain() {
			let blockhash = blockhash_and_monitor.0;
			let channel_monitor = blockhash_and_monitor.1;
			chain_listener_channel_monitors.push((
				blockhash,
				(channel_monitor, broadcaster.clone(), fee_estimator.clone(), logadapter.clone()),
				outpoint,
			));
		}

		for monitor_listener_info in chain_listener_channel_monitors.iter_mut() {
			chain_listeners.push((
				monitor_listener_info.0,
				&monitor_listener_info.1 as &dyn chain::Listen,
			));
		}
		chain_tip = Some(
			init::synchronize_listeners(
				&mut bitcoind_client,
				args.network,
				&mut cache,
				chain_listeners,
			)
			.await
			.unwrap(),
		);
	}

	// Step 11: Give ChannelMonitors to ChainMonitor
	for item in chain_listener_channel_monitors.drain(..) {
		let channel_monitor = item.1 .0;
		let funding_outpoint = item.2;
		chain_monitor.watch_channel(funding_outpoint, channel_monitor).unwrap();
	}

	// Step 13: Optional: Initialize the NetGraphMsgHandler
	// XXX persist routing data
	let genesis_hash = genesis_block(args.network).header.block_hash();
	let network_graph_path = format!("{}/network_graph", ldk_data_dir.clone());
	let network_graph =
		Arc::new(disk::read_network(Path::new(&network_graph_path), genesis_hash));

	let network_gossip = Arc::new(NetGraphMsgHandler::new(
		Arc::clone(&network_graph),
		None,
		logadapter.clone(),
	));

	disk::start_network_graph_persister(network_graph_path, &network_graph);

	// Step 14: Initialize the PeerManager
	let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);
	let mut ephemeral_bytes = [0; 32];
	rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
	let lightning_msg_handler =
		MessageHandler { chan_handler: channel_manager.clone(), route_handler: network_gossip.clone() };
	let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
		lightning_msg_handler,
		keys_manager.get_node_secret(Recipient::Node).unwrap(),
		&ephemeral_bytes,
		logadapter.clone(),
		Arc::new(IgnoringMessageHandler {}),
	));

	// ## Running LDK
	// Step 16: Initialize Peer Connection Handling

	let peer_manager_connection_handler = peer_manager.clone();
	let listening_port = args.peer_listening_port;

	let p2p_runtime = start_p2p_listener(peer_manager_connection_handler, listening_port);

	// Step 17: Connect and Disconnect Blocks
	if chain_tip.is_none() {
		chain_tip = Some(init::validate_best_block_header(&mut bitcoind_client).await.unwrap());
	}
	let channel_manager_listener = channel_manager.clone();
	let chain_monitor_listener = chain_monitor.clone();
	let network = args.network;
	tokio::spawn(async move {
		let chain_poller = poll::ChainPoller::new(&mut bitcoind_client, network);
		let chain_listener = (chain_monitor_listener, channel_manager_listener);
		let mut spv_client =
			SpvClient::new(chain_tip.unwrap(), chain_poller, &mut cache, &chain_listener);
		loop {
			spv_client.poll_best_tip().await.unwrap();
			tokio::time::sleep(Duration::new(1, 0)).await;
		}
	});

	// Step 17 & 18: Initialize ChannelManager persistence & Once Per Minute: ChannelManager's
	// timer_chan_freshness_every_min() and PeerManager's timer_tick_occurred
	let data_dir = ldk_data_dir.clone();
	let persist_channel_manager_callback =
		move |node: &ChannelManager| FilesystemPersister::persist_manager(data_dir.clone(), &*node);

	let payment_info: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));

	let params = ProbabilisticScoringParameters::default();
	let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(params, network_graph.clone())));
	let router = DefaultRouter::new(network_graph.clone(), logadapter.clone(), keys_manager.get_secure_random_bytes());
	let handle = tokio::runtime::Handle::current();

	let channel_manager_event_listener = channel_manager.clone();
	let chain_monitor_event_listener = chain_monitor.clone();
	let keys_manager_listener = keys_manager.clone();
	let payment_info_for_events = payment_info.clone();

	let event_handler = MyEventHandler {
		handle,
		channel_manager: channel_manager_event_listener,
		chain_monitor: chain_monitor_event_listener,
		bitcoind_client: bitcoind_client_arc.clone(),
		keys_manager: keys_manager_listener,
		payment_storage: payment_info_for_events,
		network,
	};

	let invoice_payer = Arc::new(InvoicePayer::new(
		channel_manager.clone(),
		router,
		scorer.clone(),
		logadapter.clone(),
		event_handler,
		payment::RetryAttempts(5),
	));

	let background_processor = BackgroundProcessor::start(
		persist_channel_manager_callback,
		invoice_payer.clone(),
		chain_monitor.clone(),
		channel_manager.clone(),
		Some(network_gossip.clone()),
		peer_manager.clone(),
		logadapter.clone(),
	);


	let peer_manager_processor = peer_manager.clone();
	tokio::spawn(async move {
		loop {
			peer_manager_processor.timer_tick_occurred();
			tokio::time::sleep(Duration::new(60, 0)).await;
		}
	});

	let (connector, network_controller) = if args.tor {
		info!("Starting Tor");
		setup_tor(&ldk_data_dir, args.name, listening_port, Arc::clone(&channel_manager)).await
	} else {
		if TorManager::is_configured(Path::new(&ldk_data_dir)) {
			panic!("Tor was previously configured, refusing to start without --tor.  Remove the `tor` directory in {} if you really want to expose your IP.", ldk_data_dir);
		}
		(Arc::new(Connector { tor: None }), NetworkController { tor: None })
	};

	// These are clones for the reconnect thread below
	let connect_cm = Arc::clone(&channel_manager);
	let connect_pm = Arc::clone(&peer_manager);
	let connect_connector = Arc::clone(&connector);

	let peer_data_path = format!("{}/channel_peer_data", ldk_data_dir.clone());

	let node = Node {
		peer_manager,
		channel_manager,
		payer: invoice_payer,
		payment_info,
		keys_manager,
		ldk_data_dir,
		bitcoind_client: bitcoind_client_arc,
		network: args.network,
		background_processor,
		chain_monitor,
		connector,
		p2p_runtime
	};

	tokio::spawn(async move {
		let mut interval = tokio::time::interval(Duration::from_secs(5));
		loop {
			interval.tick().await;
			match disk::read_channel_peer_data(Path::new(&peer_data_path)) {
				Ok(info) => {
					let peers = connect_pm.get_peer_node_ids();
					for node_id in connect_cm
						.list_channels()
						.iter()
						.map(|chan| chan.counterparty.node_id)
						.filter(|id| !peers.contains(id))
					{
						for (pubkey, peer_addr) in info.iter() {
							if *pubkey == node_id {
								// ignore errors, we'll retry later and there's logging in do_connect_peer
								let _ = connect_connector.do_connect_peer(
									*pubkey,
									peer_addr.clone(),
									Arc::clone(&connect_pm),
								).await;
							}
						}
					}
				}
				Err(e) => println!("ERROR: errored reading channel peer info from disk: {:?}", e),
			}
		}
	});

	(node, network_controller)
}

fn start_p2p_listener(peer_manager_connection_handler: Arc<PeerManager>, listening_port: u16) -> runtime::Runtime {
	let runtime = std::thread::spawn(|| {
		runtime::Builder::new_multi_thread().enable_all()
			.thread_name("p2p")
			.worker_threads(2) // for debugging
			.build()
	}).join().expect("runtime join").expect("runtime");
	let handle = runtime.handle().clone();
	handle.spawn(async move {
		let listener =
			tokio::net::TcpListener::bind(format!("0.0.0.0:{}", listening_port)).await.unwrap();
		loop {
			let tcp_stream = listener.accept().await.unwrap().0;
			let peer_mgr = peer_manager_connection_handler.clone();
			info!("accepted");
			tokio::spawn(async move {
				lightning_net_tokio::setup_inbound(
					peer_mgr,
					tcp_stream.into_std().unwrap(),
				).await;
			});
			info!("setup");
		}
	});
	runtime
}

async fn setup_tor(ldk_data_dir: &String, node_name_opt: Option<String>, listening_port: u16, channel_manager: Arc<ChannelManager>) -> (Arc<Connector>, NetworkController) {
	let tor_manager = TorManager::start(Path::new(&ldk_data_dir)).await;
	let connector = Arc::new(Connector { tor: Some(tor_manager.get_connector()) });

	if let Some(node_name) = node_name_opt {
		let onion_address = tor_manager.init_service(listening_port).await;

		// TODO: consider LDK comment replicated below:
		// In a production environment, this should occur only after the announcement of new channels
		// to avoid churn in the global network graph.
		let chan_manager = Arc::clone(&channel_manager);
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(Duration::from_secs(60));
			let mut alias = [0; 32];
			alias[..node_name.len()].copy_from_slice(node_name.as_bytes());

			let raw_address = onion_address.get_raw_bytes();
			let mut pubkey = [0u8; 32];
			let mut checksum = [0u8; 2];
			pubkey.clone_from_slice(&raw_address[0..32]);
			checksum.clone_from_slice(&raw_address[32..34]);
			let version = raw_address[34];
			assert_eq!(version, 3);

			let ldk_onion_address =
				NetAddress::OnionV3 {
					ed25519_pubkey: pubkey,
					checksum: u16::from_be_bytes(checksum),
					version: 3,
					port: listening_port
				};

			loop {
				interval.tick().await;
				info!("broadcasting node announcement as {} with {}:{}", node_name, onion_address, listening_port);
				chan_manager.broadcast_node_announcement(
					[0; 3],
					alias,
					vec![ldk_onion_address.clone()],
				);
			}
		});
	}

	let network_controller = NetworkController {
		tor: Some(tor_manager)
	};

	(connector, network_controller)
}

impl Node {
	pub fn new_invoice(&self, amt_msat: u64) -> Result<Invoice, String> {
		let mut payments = self.payment_info.lock().unwrap();
		let secp_ctx = Secp256k1::new();

		let mut preimage = [0; 32];
		rand::thread_rng().fill_bytes(&mut preimage);
		let payment_hash = Sha256Hash::hash(&preimage);

		let payment_secret = self
			.channel_manager
			.create_inbound_payment_for_hash(
				PaymentHash(payment_hash.into_inner()),
				Some(amt_msat),
				7200,
			)
			.map_err(|e| format!("{:?}", e))?;

		let our_node_pubkey = self.channel_manager.get_our_node_id();
		let mut invoice = lightning_invoice::InvoiceBuilder::new(match self.network {
			Network::Bitcoin => lightning_invoice::Currency::Bitcoin,
			Network::Testnet => lightning_invoice::Currency::BitcoinTestnet,
			Network::Regtest => lightning_invoice::Currency::Regtest,
			Network::Signet => lightning_invoice::Currency::Signet,
		})
			.payment_hash(payment_hash)
			.payment_secret(payment_secret)
			.description("lnrod invoice".to_string())
			.amount_milli_satoshis(amt_msat)
			.current_timestamp()
			.min_final_cltv_expiry(MIN_FINAL_CLTV_EXPIRY as u64)
			.payee_pub_key(our_node_pubkey);

		// Add route hints to the invoice.
		let our_channels = self.channel_manager.list_usable_channels();
		for channel in our_channels {
			let short_channel_id = match channel.short_channel_id {
				Some(id) => id,
				None => continue,
			};
			let forwarding_info = match channel.counterparty.forwarding_info {
				Some(info) => info,
				None => continue,
			};
			info!("VMW: adding routehop, info.fee base: {}", forwarding_info.fee_base_msat);
			let hops = vec![RouteHintHop {
				src_node_id: channel.counterparty.node_id,
				short_channel_id,
				cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
				htlc_minimum_msat: None,
				fees: RoutingFees {
					base_msat: forwarding_info.fee_base_msat,
					proportional_millionths: forwarding_info.fee_proportional_millionths,
				},
				htlc_maximum_msat: None,
			}];
			invoice = invoice.private_route(RouteHint(hops));
		}

		// Sign the invoice.
		let invoice = invoice
			.build_signed(|msg_hash| {
				secp_ctx.sign_recoverable(msg_hash, &self.keys_manager.get_node_secret(Recipient::Node).unwrap())
			})
			.map_err(|e| format!("{:?}", e))?;

		info!(
			"generated invoice with hash {} secret {}",
			hex::encode(payment_hash),
			hex::encode(payment_secret.0)
		);
		payments.insert(
			PaymentHash(payment_hash.into_inner()),
			(
				Some(PaymentPreimage(preimage)),
				HTLCDirection::Inbound,
				HTLCStatus::Pending,
				MilliSatoshiAmount(Some(amt_msat)),
			),
		);
		Ok(invoice)
	}

	pub fn send_payment(&self, invoice: Invoice) -> Result<(), String> {
		let status = match self.payer.pay_invoice(&invoice) {
			Ok(_payment_id) => {
				let payee_pubkey = invoice.recover_payee_pub_key();
				let amt_msat = invoice.amount_milli_satoshis().unwrap();
				info!("EVENT: initiated sending {} msats to {}", amt_msat, payee_pubkey);
				HTLCStatus::Pending
			}
			Err(PaymentError::Invoice(e)) => {
				return Err(format!("ERROR: invalid invoice: {}", e));
			}
			Err(PaymentError::Routing(e)) => {
				return Err(format!("ERROR: failed to find route: {:?}", e));
			}
			Err(PaymentError::Sending(e)) => {
				error!("ERROR: failed to send payment: {:?}", e);
				HTLCStatus::Failed
			}
		};
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let mut payments = self.payment_info.lock().unwrap();
		payments.insert(
			payment_hash,
			(None, HTLCDirection::Outbound, status, MilliSatoshiAmount(Some(invoice.amount_milli_satoshis().unwrap()))),
		);
		Ok(())
	}

	pub fn keysend_payment(&self, node_id: PublicKey, value_msat: u64) -> Result<(), String> {
		let mut payment_preimage = PaymentPreimage([0; 32]);
		thread_rng().fill_bytes(&mut payment_preimage.0);
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		let status = match self.payer.pay_pubkey(node_id, payment_preimage, value_msat, MIN_FINAL_CLTV_EXPIRY) {
			Ok(_payment_id) => {
				info!("initiated keysend of {} msat to {}", value_msat, node_id);
				HTLCStatus::Pending
			}
			Err(PaymentError::Invoice(e)) => {
				return Err(format!("ERROR: invalid invoice: {}", e));
			}
			Err(PaymentError::Routing(e)) => {
				return Err(format!("ERROR: failed to find route: {:?}", e));
			}
			Err(PaymentError::Sending(e)) => {
				error!("ERROR: failed to send payment: {:?}", e);
				HTLCStatus::Failed
			}
		};
		let mut payments = self.payment_info.lock().unwrap();
		payments.insert(
			payment_hash,
			(None, HTLCDirection::Outbound, status, MilliSatoshiAmount(Some(value_msat))),
		);
		Ok(())
	}

	pub async fn blockchain_info(&self) -> BlockchainInfo {
		self.bitcoind_client.get_blockchain_info().await
	}

	pub(crate) async fn connect_peer_if_necessary(
		&self,
		pubkey: PublicKey,
		peer_addr: HostAndPort,
		peer_manager: Arc<PeerManager>,
	) -> Result<(), ()> {
		for node_pubkey in peer_manager.get_peer_node_ids() {
			if node_pubkey == pubkey {
				return Ok(());
			}
		}

		self.connector.do_connect_peer(pubkey, peer_addr.clone(), peer_manager).await?;

		let peer_data_path = format!("{}/channel_peer_data", self.ldk_data_dir);
		disk::persist_channel_peer(
			Path::new(&peer_data_path),
			pubkey,
			peer_addr
		).expect("disk write error");

		Ok(())
	}
}
