use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fmt, io};

use log::{debug, error, info};

use bitcoin::consensus::encode;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, Transaction};
use bitcoin_bech32::WitnessProgram;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::transaction::OutPoint;
use lightning::chain::Filter;
use lightning::ln::channelmanager::ChannelManager as RLChannelManager;
use lightning::ln::peer_handler::PeerManager as RLPeerManager;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::network_graph::NetGraphMsgHandler;
use lightning::util::events::Event;
use lightning_net_tokio::SocketDescriptor;
use lightning_persister::FilesystemPersister;
use lightning_signer::lightning;
use rand::{thread_rng, Rng};

use signer::keys::{DynKeysInterface, DynSigner, SpendableKeysInterface};

use crate::bitcoind_client::BitcoindClient;
use crate::lightning::ln::peer_handler::IgnoringMessageHandler;
use crate::lightning::routing::network_graph::NetworkGraph;
use crate::logadapter::LoggerAdapter;

#[macro_use]
#[allow(unused_macros)]
pub mod macro_logger;

pub mod admin;
mod bitcoind_client;
mod byte_utils;
pub mod config;
mod convert;
mod disk;
mod fslogger;
mod hex_utils;
pub mod log_utils;
mod logadapter;
pub mod node;
pub mod signer;
pub mod util;

#[derive(PartialEq)]
pub(crate) enum HTLCDirection {
	Inbound,
	Outbound,
}

#[derive(Clone)]
pub(crate) enum HTLCStatus {
	Pending = 0,
	Succeeded = 1,
	Failed = 2,
}

pub trait SyncAccess: chain::Access + Send + Sync {}
pub trait SyncFilter: Filter + Send + Sync {}

pub(crate) struct MilliSatoshiAmount(Option<u64>);

impl fmt::Display for MilliSatoshiAmount {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.0 {
			Some(amt) => write!(f, "{}", amt),
			None => write!(f, "unknown"),
		}
	}
}

pub(crate) type PaymentInfoStorage = Arc<
	Mutex<
		HashMap<
			PaymentHash,
			(Option<PaymentPreimage>, HTLCDirection, HTLCStatus, MilliSatoshiAmount),
		>,
	>,
>;

type ArcChainMonitor = ChainMonitor<
	DynSigner,
	Arc<dyn SyncFilter>,
	Arc<BitcoindClient>,
	Arc<BitcoindClient>,
	Arc<LoggerAdapter>,
	Arc<FilesystemPersister>,
>;

pub(crate) type PeerManager = SimpleArcPeerManager<SocketDescriptor, dyn SyncAccess, LoggerAdapter>;

pub(crate) type SimpleArcPeerManager<SD, C, L> =
	RLPeerManager<SD, Arc<ChannelManager>, Arc<NetGraphMsgHandler<Arc<NetworkGraph>, Arc<C>, Arc<L>>>, Arc<L>, Arc<IgnoringMessageHandler>>;

pub(crate) type ChannelManager = RLChannelManager<
	DynSigner,
	Arc<ArcChainMonitor>,
	Arc<BitcoindClient>,
	Arc<DynKeysInterface>,
	Arc<BitcoindClient>,
	Arc<LoggerAdapter>,
>;

async fn handle_ldk_events(
	channel_manager: Arc<ChannelManager>, _chain_monitor: Arc<ArcChainMonitor>,
	bitcoind_client: Arc<BitcoindClient>, keys_manager: Arc<DynKeysInterface>,
	payment_storage: PaymentInfoStorage, network: Network,
	event: Event,
) {
	let mut pending_txs: HashMap<OutPoint, Transaction> = HashMap::new();
	match event {
		Event::FundingGenerationReady {
			temporary_channel_id,
			channel_value_satoshis,
			output_script,
			..
		} => {
			info!("EVENT: funding generation ready");
			// Construct the raw transaction with one output, that is paid the amount of the
			// channel.
			let addr = WitnessProgram::from_scriptpubkey(
				&output_script[..],
				match network {
					Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
					Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
					Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
					Network::Signet => bitcoin_bech32::constants::Network::Testnet,
				},
			)
				.expect("Lightning funding tx should always be to a SegWit output")
				.to_address();
			let mut outputs = HashMap::with_capacity(1);
			outputs.insert(addr, channel_value_satoshis);
			debug!("create_raw_transaction {:?}", outputs);
			let raw_tx = bitcoind_client.create_raw_transaction(outputs).await;

			// Have your wallet put the inputs into the transaction such that the output is
			// satisfied.
			let funded_tx = bitcoind_client.fund_raw_transaction(raw_tx).await;
			let change_output_position = funded_tx.changepos;
			assert!(change_output_position == 0 || change_output_position == 1);

			// Sign the final funding transaction and broadcast it.
			let signed_tx =
				bitcoind_client.sign_raw_transaction_with_wallet(funded_tx.hex).await;
			assert_eq!(signed_tx.complete, true);
			let final_tx: Transaction =
				encode::deserialize(&hex_utils::to_vec(&signed_tx.hex).unwrap()).unwrap();
			let outpoint = OutPoint {
				txid: final_tx.txid(),
				index: if change_output_position == 0 { 1 } else { 0 },
			};
			// Give the funding transaction back to LDK for opening the channel.
			channel_manager
				.funding_transaction_generated(&temporary_channel_id, final_tx.clone())
				.unwrap();
			pending_txs.insert(outpoint, final_tx);
		}
		Event::PaymentReceived { amt, payment_hash, .. } => {
			let mut payments = payment_storage.lock().unwrap();
			if let Some((Some(preimage), _, _, _)) = payments.get(&payment_hash) {
				let success = channel_manager.claim_funds(preimage.clone());

				if success {
					info!(
								"EVENT: received payment from payment_hash {} of {} satoshis",
								hex_utils::hex_str(&payment_hash.0),
								amt / 1000
							);
					io::stdout().flush().unwrap();
					let (_, _, ref mut status, _) =
						payments.get_mut(&payment_hash).unwrap();
					*status = HTLCStatus::Succeeded;
				} else {
					error!(
								"EVENT: failed to claim payment with {} msat, preimage {}",
								amt,
								hex::encode(preimage.0)
							);
				}
			} else {
				error!("ERROR: we received a payment but didn't know the preimage");
				io::stdout().flush().unwrap();
				channel_manager.fail_htlc_backwards(&payment_hash);
				payments.insert(
					payment_hash,
					(
						None,
						HTLCDirection::Inbound,
						HTLCStatus::Failed,
						MilliSatoshiAmount(None),
					),
				);
			}
		}
		Event::PaymentSent { payment_preimage, .. } => {
			let hashed = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
			let mut payments = payment_storage.lock().unwrap();
			for (payment_hash, (preimage_option, _, status, amt_sat)) in payments.iter_mut()
			{
				if *payment_hash == hashed {
					*preimage_option = Some(payment_preimage);
					*status = HTLCStatus::Succeeded;
					info!(
								"EVENT: successfully sent payment of {} satoshis from \
                                         payment hash {:?} with preimage {:?}",
								amt_sat,
								hex_utils::hex_str(&payment_hash.0),
								hex_utils::hex_str(&payment_preimage.0)
							);
					io::stdout().flush().unwrap();
				}
			}
		}
		Event::PaymentPathFailed {
			payment_hash,
			rejected_by_dest,
			all_paths_failed,
			short_channel_id,
			..
		} => {
			error!(
						"EVENT: Failed to send payment{} to payment hash {:?}: ",
						if all_paths_failed { "" } else { " along MPP path" },
						hex_utils::hex_str(&payment_hash.0)
					);
			if let Some(scid) = short_channel_id {
				error!(" because of failure at channel {}", scid);
			}
			if rejected_by_dest {
				error!("rejected by destination node");
			} else {
				error!("route failed");
			}
			io::stdout().flush().unwrap();

			let mut payments = payment_storage.lock().unwrap();
			if payments.contains_key(&payment_hash) {
				let (_, _, ref mut status, _) = payments.get_mut(&payment_hash).unwrap();
				*status = HTLCStatus::Failed;
			}
		}
		Event::PendingHTLCsForwardable { time_forwardable } => {
			info!("EVENT: HTLCs available for forwarding");
			let forwarding_channel_manager = channel_manager.clone();
			tokio::spawn(async move {
				let min = time_forwardable.as_millis() as u64;
				if min > 0 {
					let millis_to_sleep = thread_rng().gen_range(min, min * 5) as u64;
					tokio::time::sleep(Duration::from_millis(millis_to_sleep)).await;
				}
				forwarding_channel_manager.process_pending_htlc_forwards();
			});
		}
		Event::SpendableOutputs { outputs } => {
			info!("EVENT: got spendable outputs {:?}", outputs);
			let label = format!("sweep-{}", keys_manager.get_node_id().to_string());
			let destination_address = bitcoind_client.get_new_address(label).await;
			let output_descriptors = &outputs.iter().map(|a| a).collect::<Vec<_>>();
			let tx_feerate =
				bitcoind_client.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
			// FIXME this is not in KeysInterface
			let spending_tx = keys_manager
				.spend_spendable_outputs(
					output_descriptors,
					Vec::new(),
					destination_address.script_pubkey(),
					tx_feerate,
					&Secp256k1::new(),
				)
				.unwrap();
			bitcoind_client.broadcast_transaction(&spending_tx);
			// XXX maybe need to rescan and blah?
		}
		Event::PaymentForwarded { .. } => {}
		Event::ChannelClosed { channel_id, reason, .. } => {
			info!("EVENT: Channel {} closed due to {}", hex_utils::hex_str(&channel_id), reason);
		}
		Event::DiscardFunding { .. } => {}
	}
}

#[test]
fn test_preimage() {
	let preimage =
		hex::decode("0cd4d8d6e1df07bcc93921518dfcb9381537a239bfda7555a2948da6fcc966b0").unwrap();
	let payment_hash = PaymentHash(Sha256::hash(&preimage).into_inner());
	assert_eq!(
		hex::encode(payment_hash.0),
		"babe12b1f7ce7c610daadf397272dbbfafed71f02765109181bbc0f624dbd721"
	);
}
