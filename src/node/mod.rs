use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use lightning::ln::{channelmanager, PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{ChainParameters, ChannelManagerReadArgs, BestBlock, MIN_FINAL_CLTV_EXPIRY};
use lightning::ln::features::InvoiceFeatures;
use lightning::ln::peer_handler::MessageHandler;
use lightning::routing::network_graph::{NetGraphMsgHandler, RoutingFees};
use lightning::routing::router;
use lightning::util::logger::Level as LogLevel;
use lightning::util::logger::Logger;
use lightning::util::ser::{ReadableArgs, Writer};
use lightning_block_sync::{init, poll, SpvClient, UnboundedCache};
use lightning_invoice::Invoice;
use lightning_persister::FilesystemPersister;
use rand::{thread_rng, Rng};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

use crate::background::BackgroundProcessor;
use crate::bitcoind_client::BitcoindClient;
use crate::config::Config;
use crate::disk::FilesystemLogger;
use crate::logger::{self, AbstractLogger};
use crate::net::{setup_inbound, setup_outbound};
use crate::signer::get_keys_manager;
use crate::signer::keys::DynKeysInterface;
use crate::{disk, handle_ldk_events, ArcChainMonitor, ChannelManager, HTLCDirection, HTLCStatus, MilliSatoshiAmount, PaymentInfoStorage, PeerManager, SyncAccess};
use lightning::routing::router::RouteHintHop;
use crate::convert::BlockchainInfo;

const FINAL_CLTV_BUFFER: u32 = 6;

#[derive(Clone)]
pub struct NodeBuildArgs {
	pub bitcoind_rpc_username: String,
	pub bitcoind_rpc_password: String,
	pub bitcoind_rpc_host: String,
	pub bitcoind_rpc_port: u16,
	pub storage_dir_path: String,
	pub peer_listening_port: u16,
	pub network: Network,
	pub disk_log_level: LogLevel,
	pub console_log_level: LogLevel,
	pub signer_name: String,
	pub config: Config,
}

#[allow(dead_code)]
pub(crate) struct Node {
	pub(crate) peer_manager: Arc<PeerManager>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) router: Arc<NetGraphMsgHandler<Arc<dyn SyncAccess>, Arc<AbstractLogger>>>,
	pub(crate) payment_info: PaymentInfoStorage,
	pub(crate) keys_manager: Arc<DynKeysInterface>,
	pub(crate) event_ntfn_sender: Sender<()>,
	pub(crate) ldk_data_dir: String,
	pub(crate) bitcoind_client: Arc<BitcoindClient>,
	pub(crate) network: Network,
}

pub(crate) async fn build_node(args: NodeBuildArgs) -> Node {
	// Initialize the LDK data directory if necessary.
	let ldk_data_dir = args.storage_dir_path.clone();
	fs::create_dir_all(ldk_data_dir.clone()).unwrap();

	// Step 6: Initialize the KeysManager

	// The key seed that we use to derive the node privkey (that corresponds to the node pubkey) and
	// other secret key material.
	let keys_seed_path = format!("{}/keys_seed", ldk_data_dir.clone());
	let keys_seed = if let Ok(seed) = fs::read(keys_seed_path.clone()) {
		assert_eq!(seed.len(), 32);
		let mut key = [0; 32];
		key.copy_from_slice(&seed);
		key
	} else {
		let mut key = [0; 32];
		thread_rng().fill_bytes(&mut key);
		let mut f = File::create(keys_seed_path).unwrap();
		f.write_all(&key).expect("Failed to write node keys seed to disk");
		f.sync_all().expect("Failed to sync node keys seed to disk");
		key
	};
	let manager = get_keys_manager(args.signer_name.as_str(), &keys_seed).unwrap();
	let keys_manager = Arc::new(DynKeysInterface::new(manager));

	build_with_signer(keys_manager, args, ldk_data_dir).await
}

async fn build_with_signer(
	keys_manager: Arc<DynKeysInterface>, args: NodeBuildArgs, ldk_data_dir: String,
) -> Node {
	// Initialize our bitcoind client.
	let mut bitcoind_client = BitcoindClient::new(
		args.bitcoind_rpc_host.clone(),
		args.bitcoind_rpc_port,
		args.bitcoind_rpc_username.clone(),
		args.bitcoind_rpc_password.clone(),
	)
	.await
	.unwrap_or_else(|e| panic!("Failed to connect to bitcoind client: {}", e));

	let bitcoind_client_arc = Arc::new(bitcoind_client.clone());
	// ## Setup
	// Step 1: Initialize the FeeEstimator

	// BitcoindClient implements the FeeEstimator trait, so it'll act as our fee estimator.
	let fee_estimator = Arc::clone(&bitcoind_client_arc);

	// Step 2: Initialize the Logger
	// TODO(ksedgwic) - Resolve data_dir setup and move this to main_server because earlier.
	let is_daemon = false;
	let console_log_level = if is_daemon { LogLevel::Off } else { args.console_log_level };
	logger::set(Arc::new(AbstractLogger::new(Box::new(FilesystemLogger::new(
		ldk_data_dir.clone(),
		args.disk_log_level,
		console_log_level,
	)))));

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
		logger::get(),
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
	let (channel_manager_blockhash, mut channel_manager) = {
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
				logger::get(),
				user_config,
				channel_monitor_mut_references,
			);
			<(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
		} else {
			// We're starting a fresh node.
			restarting_node = false;
			let getinfo_resp = bitcoind_client.get_blockchain_info().await;
			let best_block = BestBlock::new(getinfo_resp.latest_blockhash,
											getinfo_resp.latest_height as u32);
			let chain_params = ChainParameters {
				network: args.network,
				best_block,
			};
			let fresh_channel_manager = channelmanager::ChannelManager::new(
				fee_estimator.clone(),
				chain_monitor.clone(),
				broadcaster.clone(),
				logger::get(),
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
			vec![(channel_manager_blockhash, &mut channel_manager as &mut dyn chain::Listen)];

		for (outpoint, blockhash_and_monitor) in outpoint_to_channelmonitor.drain() {
			let blockhash = blockhash_and_monitor.0;
			let channel_monitor = blockhash_and_monitor.1;
			chain_listener_channel_monitors.push((
				blockhash,
				(channel_monitor, broadcaster.clone(), fee_estimator.clone(), logger::get()),
				outpoint,
			));
		}

		for monitor_listener_info in chain_listener_channel_monitors.iter_mut() {
			chain_listeners.push((
				monitor_listener_info.0,
				&mut monitor_listener_info.1 as &mut dyn chain::Listen,
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
	let genesis = genesis_block(args.network).header.block_hash();
	let router =
		Arc::new(NetGraphMsgHandler::new(genesis, None::<Arc<dyn SyncAccess>>, logger::get()));

	// Step 14: Initialize the PeerManager
	let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);
	let mut ephemeral_bytes = [0; 32];
	rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
	let lightning_msg_handler =
		MessageHandler { chan_handler: channel_manager.clone(), route_handler: router.clone() };
	let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
		lightning_msg_handler,
		keys_manager.get_node_secret(),
		&ephemeral_bytes,
		logger::get(),
	));

	// ## Running LDK
	// Step 16: Initialize Peer Connection Handling

	// We poll for events in handle_ldk_events(..) rather than waiting for them over the
	// mpsc::channel, so we can leave the event receiver as unused.
	let (event_ntfn_sender, mut event_ntfn_receiver) = mpsc::channel(2);
	let peer_manager_connection_handler = peer_manager.clone();
	let listening_port = args.peer_listening_port;
	let event_ntfn_sender1 = event_ntfn_sender.clone();
	tokio::spawn(async move {
		loop {
			let item = event_ntfn_receiver.recv().await;
			if item.is_none() {
				break;
			}
		}
	});

	tokio::spawn(async move {
		let listener =
			tokio::net::TcpListener::bind(format!("0.0.0.0:{}", listening_port)).await.unwrap();
		loop {
			let tcp_stream = listener.accept().await.unwrap().0;
			log_info!("accepted");
			setup_inbound(
				peer_manager_connection_handler.clone(),
				event_ntfn_sender1.clone(),
				tcp_stream,
			)
			.await
			.unwrap();
			log_info!("setup");
		}
	});

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
	let _background = BackgroundProcessor::start(
		persist_channel_manager_callback,
		channel_manager.clone(),
		peer_manager.clone(),
	)
	.await;

	let peer_manager_processor = peer_manager.clone();
	tokio::spawn(async move {
		loop {
			peer_manager_processor.timer_tick_occurred();
			tokio::time::sleep(Duration::new(60, 0)).await;
		}
	});

	// Step 15: Initialize LDK Event Handling
	let channel_manager_event_listener = channel_manager.clone();
	let chain_monitor_event_listener = chain_monitor.clone();
	let keys_manager_listener = keys_manager.clone();
	let payment_info: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
	let payment_info_for_events = payment_info.clone();
	let network = args.network;
	tokio::spawn(handle_ldk_events(
		channel_manager_event_listener,
		chain_monitor_event_listener,
		bitcoind_client_arc.clone(),
		keys_manager_listener,
		payment_info_for_events,
		network,
	));

	Node {
		peer_manager,
		channel_manager,
		router,
		payment_info,
		keys_manager,
		event_ntfn_sender,
		ldk_data_dir,
		bitcoind_client: bitcoind_client_arc,
		network: args.network,
	}
}

pub(crate) async fn connect_peer_if_necessary(
	pubkey: PublicKey, peer_addr: SocketAddr, peer_manager: Arc<PeerManager>,
	event_notifier: mpsc::Sender<()>,
) -> Result<(), ()> {
	for node_pubkey in peer_manager.get_peer_node_ids() {
		if node_pubkey == pubkey {
			return Ok(());
		}
	}
	match tokio::net::TcpStream::connect(&peer_addr).await {
		Ok(stream) => {
			let peer_mgr = peer_manager.clone();
			let event_ntfns = event_notifier.clone();
			tokio::spawn(setup_outbound(peer_mgr, event_ntfns, pubkey, stream));
			let mut peer_connected = false;
			for _ in 0..5 {
				for node_pubkey in peer_manager.get_peer_node_ids() {
					if node_pubkey == pubkey {
						peer_connected = true;
					}
				}
				if peer_connected {
					break;
				}
				log_info!("waiting for peer connection setup");
				tokio::time::sleep(Duration::new(1, 0)).await;
			}
			if !peer_connected {
				log_info!("timed out setting up peer connection");
				return Err(());
			}
		}
		Err(e) => {
			log_info!("ERROR: failed to connect to peer: {:?}", e);
			return Err(());
		}
	}
	Ok(())
}

impl Node {
	pub fn new_invoice(&self, amt_msat: u64) -> Result<Invoice, String> {
		let mut payments = self.payment_info.lock().unwrap();
		let secp_ctx = Secp256k1::new();

		let mut preimage = [0; 32];
		rand::thread_rng().fill_bytes(&mut preimage);
		let payment_hash = Sha256Hash::hash(&preimage);

		let payment_secret =
			self.channel_manager.create_inbound_payment_for_hash(
				PaymentHash(payment_hash.into_inner()),
				Some(amt_msat),
				7200, 0)
				.map_err(|e| format!("{:?}", e))?;

		let our_node_pubkey = self.channel_manager.get_our_node_id();
		let mut invoice = lightning_invoice::InvoiceBuilder::new(match self.network {
			Network::Bitcoin => lightning_invoice::Currency::Bitcoin,
			Network::Testnet => lightning_invoice::Currency::BitcoinTestnet,
			Network::Regtest => lightning_invoice::Currency::Regtest,
			Network::Signet => lightning_invoice::Currency::BitcoinTestnet,
		})
			.payment_hash(payment_hash)
			.payment_secret(payment_secret)
			.description("lnrod invoice".to_string())
			.amount_pico_btc(amt_msat * 10)
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
			let forwarding_info = match channel.counterparty_forwarding_info {
				Some(info) => info,
				None => continue,
			};
			log_info!("VMW: adding routehop, info.fee base: {}", forwarding_info.fee_base_msat);
			invoice = invoice.route(vec![RouteHintHop {
				src_node_id: channel.remote_network_id,
				short_channel_id,
				cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
				htlc_minimum_msat: None,
				fees: RoutingFees {
					base_msat: forwarding_info.fee_base_msat,
					proportional_millionths: forwarding_info.fee_proportional_millionths
				},
				htlc_maximum_msat: None
			}]);
		}

		// Sign the invoice.
		let invoice = invoice.build_signed(|msg_hash| {
			secp_ctx.sign_recoverable(msg_hash, &self.keys_manager.get_node_secret())
		}).map_err(|e| format!("{:?}", e))?;

		log_info!("generated invoice with hash {} secret {}", hex::encode(payment_hash), hex::encode(payment_secret.0));
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
		let amt_pico_btc = invoice.amount_pico_btc();
		let amt_msat = amt_pico_btc.unwrap() / 10;

		let payee_pubkey = invoice.recover_payee_pub_key();
		let final_cltv = invoice.min_final_cltv_expiry() as u32 + FINAL_CLTV_BUFFER;

		let mut payment_hash = PaymentHash([0; 32]);
		payment_hash.0.copy_from_slice(&invoice.payment_hash().as_ref()[0..32]);

		let payment_secret = match invoice.payment_secret() {
			Some(secret) => {
				let mut payment_secret = PaymentSecret([0; 32]);
				payment_secret.0.copy_from_slice(&secret.0);
				Some(payment_secret)
			}
			None => None,
		};

		let features = invoice.features().map(|f| f.clone());
		log_debug!("Sending payment with secret {:?} features {:?}", payment_secret, features);

		self.do_send_payment(
			payee_pubkey,
			amt_msat,
			final_cltv,
			payment_hash,
			payment_secret,
			features,
		)
	}

	fn do_send_payment(
		&self, payee: PublicKey, amt_msat: u64, final_cltv: u32, payment_hash: PaymentHash,
		payment_secret: Option<PaymentSecret>, payee_features: Option<InvoiceFeatures>,
	) -> Result<(), String> {
		let network_graph = self.router.network_graph.read().unwrap();
		let first_hops = self.channel_manager.list_usable_channels();
		let payer_pubkey = self.channel_manager.get_our_node_id();

		let route = router::get_route(
			&payer_pubkey,
			&network_graph,
			&payee,
			payee_features,
			Some(&first_hops.iter().collect::<Vec<_>>()),
			&vec![],
			amt_msat,
			final_cltv,
			logger::get(),
		);
		if let Err(e) = route {
			log_info!("ERROR: failed to find route: {}", e.err);
			return Err(e.err);
		}
		let status =
			match self.channel_manager.send_payment(&route.unwrap(), payment_hash, &payment_secret)
			{
				Ok(()) => {
					log_info!("EVENT: initiated sending {} msats to {}", amt_msat, payee);
					HTLCStatus::Pending
				}
				Err(e) => {
					log_info!("ERROR: failed to send payment: {:?}", e);
					HTLCStatus::Failed
				}
			};
		let mut payments = self.payment_info.lock().unwrap();
		payments.insert(
			payment_hash,
			(None, HTLCDirection::Outbound, status, MilliSatoshiAmount(Some(amt_msat))),
		);
		Ok(())
	}

	pub async fn blockchain_info(&self) -> BlockchainInfo {
		self.bitcoind_client.get_blockchain_info().await
	}
}
