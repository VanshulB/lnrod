use std::{fs, thread};
use rand::{thread_rng, Rng};
use std::fs::File;
use std::time::{SystemTime, Duration};
use std::sync::{Arc, Mutex};
use lightning_persister::FilesystemPersister;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::util::config::UserConfig;
use lightning::ln::channelmanager::{ChannelManagerReadArgs, ChainParameters};
use bitcoin::{BlockHash, Network};
use lightning::util::ser::{ReadableArgs, Writer};
use crate::default_signer::InMemorySignerFactory;
use crate::keys::{KeysManager, DynKeysInterface};
use crate::bitcoind_client::BitcoindClient;
use crate::disk::FilesystemLogger;
use crate::{disk, ArcChainMonitor, ChannelManager, PeerManager, PaymentInfoStorage, handle_ldk_events};
use lightning::ln::channelmanager;
use lightning_block_sync::{UnboundedCache, poll, init, SpvClient};
use lightning::chain;
use lightning::chain::Watch;
use bitcoin::blockdata::constants::genesis_block;
use lightning::routing::network_graph::NetGraphMsgHandler;
use lightning::ln::peer_handler::MessageHandler;
use lightning::chain::keysinterface::KeysInterface;
use tokio::sync::mpsc;
use bitcoin::secp256k1::PublicKey;
use lightning_background_processor::BackgroundProcessor;
use std::collections::HashMap;
use tokio::sync::mpsc::{Sender, Receiver};
use crate::cli::LdkUserInfo;
use std::net::{SocketAddr, TcpStream};
use tokio::runtime::Runtime;

#[allow(dead_code)]
pub(crate) struct Node {
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) channel_manager: Arc<ChannelManager>,
    pub(crate) router: Arc<NetGraphMsgHandler<Arc<dyn chain::Access>, Arc<FilesystemLogger>>>,
    pub(crate) payment_info: PaymentInfoStorage,
    pub(crate) keys_manager: Arc<DynKeysInterface>,
    pub(crate) event_ntfns: (Sender<()>, Receiver<()>),
    pub(crate) ldk_data_dir: String,
    pub(crate) logger: Arc<FilesystemLogger>,
    pub(crate) network: Network,
    pub(crate) runtime: Arc<Runtime>,
}

pub(crate) fn build_node(args: LdkUserInfo) -> Node {
    // Initialize the LDK data directory if necessary.
    let ldk_data_dir = format!("{}/.ldk", args.ldk_storage_dir_path);
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
    let cur = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let factory = InMemorySignerFactory::new(&keys_seed);
    let manager = Box::new(KeysManager::new(&keys_seed, cur.as_secs(), cur.subsec_nanos(), factory));
    let keys_manager = Arc::new(DynKeysInterface::new(manager));

    build1(keys_manager, args, ldk_data_dir)
}

fn build1(keys_manager: Arc<DynKeysInterface>, args: LdkUserInfo, ldk_data_dir: String) -> Node {
    // Initialize our bitcoind client.
    let bitcoind_client = match BitcoindClient::new(
        args.bitcoind_rpc_host.clone(),
        args.bitcoind_rpc_port,
        args.bitcoind_rpc_username.clone(),
        args.bitcoind_rpc_password.clone(),
    ) {
        Ok(client) => Arc::new(client),
        Err(e) => {
            panic!("Failed to connect to bitcoind client: {}", e);
        }
    };
    let mut bitcoind_rpc_client = bitcoind_client.get_new_rpc_client().unwrap();

    // ## Setup
    // Step 1: Initialize the FeeEstimator

    // BitcoindClient implements the FeeEstimator trait, so it'll act as our fee estimator.
    let fee_estimator = bitcoind_client.clone();

    // Step 2: Initialize the Logger
    let logger = Arc::new(FilesystemLogger::new(ldk_data_dir.clone()));

    // Step 3: Initialize the BroadcasterInterface

    // BitcoindClient implements the BroadcasterInterface trait, so it'll act as our transaction
    // broadcaster.
    let broadcaster = bitcoind_client.clone();

    // Step 4: Initialize Persist
    let persister = Arc::new(FilesystemPersister::new(ldk_data_dir.clone()));

    // Step 5: Initialize the ChainMonitor
    let chain_monitor: Arc<ArcChainMonitor> = Arc::new(ChainMonitor::new(
        None,
        broadcaster.clone(),
        logger.clone(),
        fee_estimator.clone(),
        persister.clone(),
    ));

    // Step 7: Read ChannelMonitor state from disk
    let monitors_path = format!("{}/monitors", ldk_data_dir.clone());
    let mut outpoint_to_channelmonitor =
        disk::read_channelmonitors(monitors_path.to_string(), keys_manager.clone()).unwrap();

    // Step 9: Initialize the ChannelManager
    let user_config = UserConfig::default();
    let runtime = Runtime::new().unwrap();

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
                logger.clone(),
                user_config,
                channel_monitor_mut_references,
            );
            <(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
        } else {
            // We're starting a fresh node.
            restarting_node = false;
            let getinfo_resp = bitcoind_client.get_blockchain_info();
            let chain_params = ChainParameters {
                network: args.network,
                latest_hash: getinfo_resp.latest_blockhash,
                latest_height: getinfo_resp.latest_height,
            };
            let fresh_channel_manager = channelmanager::ChannelManager::new(
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                logger.clone(),
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
                (channel_monitor, broadcaster.clone(), fee_estimator.clone(), logger.clone()),
                outpoint,
            ));
        }

        for monitor_listener_info in chain_listener_channel_monitors.iter_mut() {
            chain_listeners.push((
                monitor_listener_info.0,
                &mut monitor_listener_info.1 as &mut dyn chain::Listen,
            ));
        }
        chain_tip = Some(runtime.block_on(
            init::synchronize_listeners(
                &mut bitcoind_rpc_client,
                args.network,
                &mut cache,
                chain_listeners,
            )).unwrap(),
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
        Arc::new(NetGraphMsgHandler::new(genesis, None::<Arc<dyn chain::Access>>, logger.clone()));

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
        logger.clone(),
    ));

    // ## Running LDK
    // Step 16: Initialize Peer Connection Handling

    // We poll for events in handle_ldk_events(..) rather than waiting for them over the
    // mpsc::channel, so we can leave the event receiver as unused.
    let (event_ntfn_sender, event_ntfn_receiver) = mpsc::channel(2);
    let peer_manager_connection_handler = peer_manager.clone();
    let listening_port = args.ldk_peer_listening_port;
    let event_ntfn_sender1 = event_ntfn_sender.clone();
    runtime.spawn(async move {
        let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", listening_port)).unwrap();
        loop {
            let tcp_stream = listener.accept().unwrap().0;
            println!("accepted");
            lightning_net_tokio::setup_inbound(
                peer_manager_connection_handler.clone(),
                event_ntfn_sender1.clone(),
                tcp_stream,
            ).await;
            println!("setup");
        }
    });

    // Step 17: Connect and Disconnect Blocks
    if chain_tip.is_none() {
        chain_tip = Some(runtime.block_on(
            init::validate_best_block_header(&mut bitcoind_rpc_client)).unwrap());
    }
    let channel_manager_listener = channel_manager.clone();
    let chain_monitor_listener = chain_monitor.clone();
    let network = args.network;
    runtime.spawn(async move {
        let chain_poller = poll::ChainPoller::new(&mut bitcoind_rpc_client, network);
        let chain_listener = (chain_monitor_listener, channel_manager_listener);
        let mut spv_client =
            SpvClient::new(chain_tip.unwrap(), chain_poller, &mut cache, &chain_listener);
        loop {
            spv_client.poll_best_tip().await.unwrap();
            thread::sleep(Duration::new(1, 0));
        }
    });

    // Step 17 & 18: Initialize ChannelManager persistence & Once Per Minute: ChannelManager's
    // timer_chan_freshness_every_min() and PeerManager's timer_tick_occurred
    let handle = runtime.handle();
    let data_dir = ldk_data_dir.clone();
    let persist_channel_manager_callback =
        move |node: &ChannelManager| FilesystemPersister::persist_manager(data_dir.clone(), &*node);
    BackgroundProcessor::start(
        persist_channel_manager_callback,
        channel_manager.clone(),
        peer_manager.clone(),
        logger.clone()
    );

    let peer_manager_processor = peer_manager.clone();
    handle.spawn(async move {
        loop {
            peer_manager_processor.timer_tick_occurred();
            thread::sleep(Duration::new(60, 0));
        }
    });

    // Step 15: Initialize LDK Event Handling
    let peer_manager_event_listener = peer_manager.clone();
    let channel_manager_event_listener = channel_manager.clone();
    let chain_monitor_event_listener = chain_monitor.clone();
    let keys_manager_listener = keys_manager.clone();
    let payment_info: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
    let payment_info_for_events = payment_info.clone();
    let network = args.network;
    thread::spawn(move || {
        handle_ldk_events(
            peer_manager_event_listener,
            channel_manager_event_listener,
            chain_monitor_event_listener,
            bitcoind_client.clone(),
            keys_manager_listener,
            payment_info_for_events,
            network,
        );
    });

    Node {
        peer_manager,
        channel_manager,
        router,
        payment_info,
        keys_manager,
        event_ntfns: (event_ntfn_sender, event_ntfn_receiver),
        ldk_data_dir,
        logger,
        network: args.network,
        runtime: Arc::new(runtime)
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
    match TcpStream::connect_timeout(&peer_addr, Duration::from_secs(10)) {
        Ok(stream) => {
            let peer_mgr = peer_manager.clone();
            let event_ntfns = event_notifier.clone();
            tokio::spawn(lightning_net_tokio::setup_outbound(peer_mgr, event_ntfns, pubkey, stream));
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
                println!("waiting for peer connection setup");
                thread::sleep(Duration::new(1, 0));
            }
            if !peer_connected {
                println!("timed out setting up peer connection");
                return Err(())
            }
        }
        Err(e) => {
            println!("ERROR: failed to connect to peer: {:?}", e);
            return Err(());
        }
    }
    Ok(())
}
