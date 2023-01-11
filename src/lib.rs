use std::collections::hash_map::Entry;
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
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::transaction::OutPoint;
use lightning::chain::Filter;
use lightning::ln::channelmanager::ChannelManager as RLChannelManager;
use lightning::ln::peer_handler::IgnoringMessageHandler;
use lightning::ln::peer_handler::PeerManager as RLPeerManager;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::util::events::Event;
use lightning_net_tokio::SocketDescriptor;
use lightning_persister::FilesystemPersister;
use lightning_signer::bitcoin::Address;
use lightning_signer::{bitcoin, lightning, lightning_invoice};
use rand::{thread_rng, Rng};

use vls_protocol_client::{DynKeysInterface, DynSigner, SpendableKeysInterface};

use crate::lightning::ln::PaymentSecret;
use crate::lightning::util::events::PaymentPurpose;
use bitcoind_client::BitcoindClient;
use logadapter::LoggerAdapter;

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
pub mod net;
pub mod node;
pub mod signer;
pub mod tor;
pub mod util;

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

pub(crate) struct PaymentInfo {
	preimage: Option<PaymentPreimage>,
	secret: Option<PaymentSecret>,
	status: HTLCStatus,
	amt_msat: MilliSatoshiAmount,
}

pub(crate) type PaymentInfoStorage = Arc<Mutex<HashMap<PaymentHash, PaymentInfo>>>;

type ArcChainMonitor = ChainMonitor<
	DynSigner,
	Arc<dyn SyncFilter>,
	Arc<BitcoindClient>,
	Arc<BitcoindClient>,
	Arc<LoggerAdapter>,
	Arc<FilesystemPersister>,
>;

pub(crate) type PeerManager = SimpleArcPeerManager<SocketDescriptor, dyn SyncAccess, LoggerAdapter>;

pub(crate) type SimpleArcPeerManager<SD, C, L> = RLPeerManager<
	SD,
	Arc<ChannelManager>,
	Arc<P2PGossipSync<Arc<NetworkGraph<Arc<L>>>, Arc<C>, Arc<L>>>,
	Arc<IgnoringMessageHandler>,
	Arc<L>,
	IgnoringMessageHandler,
>;

pub(crate) type ChannelManager = RLChannelManager<
	Arc<ArcChainMonitor>,
	Arc<BitcoindClient>,
	Arc<DynKeysInterface>,
	Arc<BitcoindClient>,
	Arc<LoggerAdapter>,
>;

async fn handle_ldk_events(
	channel_manager: Arc<ChannelManager>, _chain_monitor: Arc<ArcChainMonitor>,
	bitcoind_client: Arc<BitcoindClient>, keys_manager: Arc<DynKeysInterface>,
	inbound_payments: PaymentInfoStorage, outbound_payments: PaymentInfoStorage, network: Network,
	event: Event,
) {
	let mut pending_txs: HashMap<OutPoint, Transaction> = HashMap::new();
	match event {
		Event::ProbeSuccessful { .. }
		| Event::ProbeFailed { .. }
		| Event::HTLCHandlingFailed { .. }
		| Event::HTLCIntercepted { .. } => todo!(),
		Event::FundingGenerationReady {
			temporary_channel_id,
			channel_value_satoshis,
			output_script,
			counterparty_node_id,
			..
		} => {
			info!("EVENT: funding generation ready");
			assert!(
				output_script.is_witness_program(),
				"Lightning funding tx should always be to a SegWit output"
			);
			// Construct the raw transaction with one output, that is paid the amount of the
			// channel.
			let addr = Address::from_script(&output_script, network)
				.expect("construct address from scriptpubkey");
			let mut outputs = HashMap::with_capacity(1);
			outputs.insert(addr.to_string(), channel_value_satoshis);
			debug!("create_raw_transaction {:?}", outputs);
			let raw_tx = bitcoind_client.create_raw_transaction(outputs).await;

			// Have your wallet put the inputs into the transaction such that the output is
			// satisfied.
			let funded_tx = bitcoind_client.fund_raw_transaction(raw_tx).await;
			let change_output_position = funded_tx.changepos;

			// it's possible there is no change, if we have a lot of small coins in the bitcoind wallet
			assert!(
				change_output_position == 0
					|| change_output_position == 1
					|| change_output_position == -1,
				"unexpected change output position {}",
				change_output_position
			);

			// Sign the final funding transaction and broadcast it.
			let signed_tx = bitcoind_client.sign_raw_transaction_with_wallet(funded_tx.hex).await;
			assert_eq!(signed_tx.complete, true);
			let final_tx: Transaction =
				encode::deserialize(&hex_utils::to_vec(&signed_tx.hex).unwrap()).unwrap();
			// if we have a change output at index 0, the funding output is at index 1
			// in all other cases, the funding output is at index 0
			let funding_index = if change_output_position == 0 { 1 } else { 0 };
			let outpoint = OutPoint { txid: final_tx.txid(), index: funding_index };
			// Give the funding transaction back to LDK for opening the channel.
			channel_manager
				.funding_transaction_generated(
					&temporary_channel_id,
					&counterparty_node_id,
					final_tx.clone(),
				)
				.unwrap();
			pending_txs.insert(outpoint, final_tx);
		}
		Event::PaymentClaimable { amount_msat, purpose, payment_hash, .. } => {
			let payment_preimage = match purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, .. } => payment_preimage,
				PaymentPurpose::SpontaneousPayment(preimage) => Some(preimage),
			};
			info!(
				"EVENT: received payment from payment_hash {} of {} satoshis",
				hex_utils::hex_str(&payment_hash.0),
				amount_msat / 1000
			);
			io::stdout().flush().unwrap();
			channel_manager.claim_funds(payment_preimage.unwrap());
		}
		Event::PaymentClaimed { payment_hash, purpose, amount_msat, .. } => {
			info!(
				"EVENT: claimed payment from payment_hash {} of {} satoshis",
				hex_utils::hex_str(&payment_hash.0),
				amount_msat / 1000
			);
			io::stdout().flush().unwrap();
			let (payment_preimage, payment_secret) = match purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
					(payment_preimage, Some(payment_secret))
				}
				PaymentPurpose::SpontaneousPayment(preimage) => (Some(preimage), None),
			};
			let mut payments = inbound_payments.lock().unwrap();
			match payments.entry(payment_hash) {
				Entry::Occupied(mut e) => {
					let payment = e.get_mut();
					payment.status = HTLCStatus::Succeeded;
					payment.preimage = payment_preimage;
					payment.secret = payment_secret;
				}
				Entry::Vacant(e) => {
					e.insert(PaymentInfo {
						preimage: payment_preimage,
						secret: payment_secret,
						status: HTLCStatus::Succeeded,
						amt_msat: MilliSatoshiAmount(Some(amount_msat)),
					});
				}
			}
		}
		Event::PaymentSent { payment_preimage, .. } => {
			let hashed = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
			let mut payments = outbound_payments.lock().unwrap();
			for (hash, payment) in payments.iter_mut() {
				if *hash == hashed {
					payment.preimage = Some(payment_preimage);
					payment.status = HTLCStatus::Succeeded;
					info!(
						"EVENT: successfully sent payment of {} milli-satoshis from \
                                         payment hash {:?} with preimage {:?}",
						payment.amt_msat,
						hex_utils::hex_str(&hash.0),
						hex_utils::hex_str(&payment_preimage.0)
					);
					io::stdout().flush().unwrap();
				}
			}
		}
		Event::PaymentPathFailed {
			payment_hash,
			payment_failed_permanently,
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
			if payment_failed_permanently {
				error!("rejected by destination node");
			} else {
				error!("route failed");
			}
			io::stdout().flush().unwrap();

			let mut payments = outbound_payments.lock().unwrap();
			if payments.contains_key(&payment_hash) {
				let payment = payments.get_mut(&payment_hash).unwrap();
				payment.status = HTLCStatus::Failed;
			}
		}
		Event::PendingHTLCsForwardable { time_forwardable } => {
			info!("EVENT: HTLCs available for forwarding");
			let forwarding_channel_manager = channel_manager.clone();
			tokio::spawn(async move {
				let min = time_forwardable.as_millis() as u64;
				if min > 0 {
					let millis_to_sleep = thread_rng().gen_range(min..min * 5) as u64;
					tokio::time::sleep(Duration::from_millis(millis_to_sleep)).await;
				}
				forwarding_channel_manager.process_pending_htlc_forwards();
			});
		}
		Event::SpendableOutputs { outputs } => {
			info!("EVENT: got spendable outputs {:?}", outputs);
			let sweep_address = keys_manager.get_sweep_address();
			let output_descriptors = &outputs.iter().map(|a| a).collect::<Vec<_>>();
			let tx_feerate =
				bitcoind_client.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
			// FIXME this is not in KeysInterface
			let spending_tx = keys_manager
				.spend_spendable_outputs(
					output_descriptors,
					Vec::new(),
					sweep_address.script_pubkey(),
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
		Event::DiscardFunding { .. } => {
			info!("EVENT: discard funding")
		}
		Event::PaymentFailed { payment_hash, .. } => {
			error!(
				"EVENT: payment failed to payment hash {:?}",
				hex_utils::hex_str(&payment_hash.0)
			);
		}
		Event::PaymentPathSuccessful { payment_hash, .. } => {
			info!(
				"EVENT: payment path successful for payment hash {:?}",
				payment_hash.map(|p| hex_utils::hex_str(&p.0))
			);
		}
		Event::OpenChannelRequest { .. } => {
			unimplemented!("OpenChannelRequest");
		}
		Event::ChannelReady { channel_id, .. } => {
			info!("EVENT: Channel {} ready", hex_utils::hex_str(&channel_id));
		}
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
