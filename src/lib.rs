use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fmt, io, thread};

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
use lightning::ln::channelmanager::{PaymentHash, PaymentPreimage};
use lightning::ln::peer_handler::PeerManager as RLPeerManager;
use lightning::routing::network_graph::NetGraphMsgHandler;
use lightning::util::events::{Event, EventsProvider};
use lightning_persister::FilesystemPersister;
use rand::{thread_rng, Rng};

use crate::bitcoind_client::BitcoindClient;
use crate::disk::FilesystemLogger;
use crate::keys::{DynKeysInterface, DynSigner, SpendableKeysInterface};
use crate::net::SocketDescriptor;

pub mod admin;
mod bitcoind_client;
mod byte_utils;
mod convert;
mod default_signer;
mod disk;
mod hex_utils;
mod keys;
pub mod net;
pub mod node;
mod transaction_utils;
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
	Arc<dyn Filter>,
	Arc<BitcoindClient>,
	Arc<BitcoindClient>,
	Arc<FilesystemLogger>,
	Arc<FilesystemPersister>,
>;

pub(crate) type PeerManager =
	SimpleArcPeerManager<SocketDescriptor, dyn chain::Access, FilesystemLogger>;

pub(crate) type SimpleArcPeerManager<SD, C, L> =
	RLPeerManager<SD, Arc<ChannelManager>, Arc<NetGraphMsgHandler<Arc<C>, Arc<L>>>, Arc<L>>;

pub(crate) type ChannelManager = RLChannelManager<
	DynSigner,
	Arc<ArcChainMonitor>,
	Arc<BitcoindClient>,
	Arc<DynKeysInterface>,
	Arc<BitcoindClient>,
	Arc<FilesystemLogger>,
>;

fn handle_ldk_events(
	peer_manager: Arc<PeerManager>, channel_manager: Arc<ChannelManager>,
	chain_monitor: Arc<ArcChainMonitor>, bitcoind_client: Arc<BitcoindClient>,
	keys_manager: Arc<DynKeysInterface>, payment_storage: PaymentInfoStorage, network: Network,
) {
	let mut pending_txs: HashMap<OutPoint, Transaction> = HashMap::new();
	loop {
		peer_manager.process_events();
		let loop_channel_manager = channel_manager.clone();
		let mut events = channel_manager.get_and_clear_pending_events();
		events.append(&mut chain_monitor.get_and_clear_pending_events());
		for event in events {
			match event {
				Event::FundingGenerationReady {
					temporary_channel_id,
					channel_value_satoshis,
					output_script,
					..
				} => {
					// Construct the raw transaction with one output, that is paid the amount of the
					// channel.
					let addr = WitnessProgram::from_scriptpubkey(
						&output_script[..],
						match network {
							Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
							Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
							Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
							Network::Signet => panic!("Signet unsupported"),
						},
					)
					.expect("Lightning funding tx should always be to a SegWit output")
					.to_address();
					let mut outputs = vec![HashMap::with_capacity(1)];
					outputs[0].insert(addr, channel_value_satoshis as f64 / 100_000_000.0);
					let raw_tx = bitcoind_client.create_raw_transaction(outputs);

					// Have your wallet put the inputs into the transaction such that the output is
					// satisfied.
					let funded_tx = bitcoind_client.fund_raw_transaction(raw_tx);
					let change_output_position = funded_tx.changepos;
					assert!(change_output_position == 0 || change_output_position == 1);

					// Sign the final funding transaction and broadcast it.
					let signed_tx = bitcoind_client.sign_raw_transaction_with_wallet(funded_tx.hex);
					assert_eq!(signed_tx.complete, true);
					let final_tx: Transaction =
						encode::deserialize(&hex_utils::to_vec(&signed_tx.hex).unwrap()).unwrap();
					let outpoint = OutPoint {
						txid: final_tx.txid(),
						index: if change_output_position == 0 { 1 } else { 0 },
					};
					// Give the funding transaction back to LDK for opening the channel.
					loop_channel_manager
						.funding_transaction_generated(&temporary_channel_id, final_tx.clone())
						.unwrap();
					pending_txs.insert(outpoint, final_tx);
				}
				Event::PaymentReceived { payment_hash, payment_secret, amt: amt_msat } => {
					let mut payments = payment_storage.lock().unwrap();
					if let Some((Some(preimage), _, _, _)) = payments.get(&payment_hash) {
						assert!(loop_channel_manager.claim_funds(
							preimage.clone(),
							&payment_secret,
							amt_msat
						));
						println!(
							"\nEVENT: received payment from payment_hash {} of {} satoshis",
							hex_utils::hex_str(&payment_hash.0),
							amt_msat / 1000
						);
						print!("> ");
						io::stdout().flush().unwrap();
						let (_, _, ref mut status, _) = payments.get_mut(&payment_hash).unwrap();
						*status = HTLCStatus::Succeeded;
					} else {
						println!("\nERROR: we received a payment but didn't know the preimage");
						print!("> ");
						io::stdout().flush().unwrap();
						loop_channel_manager.fail_htlc_backwards(&payment_hash, &payment_secret);
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
				Event::PaymentSent { payment_preimage } => {
					let hashed = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
					let mut payments = payment_storage.lock().unwrap();
					for (payment_hash, (preimage_option, _, status, amt_sat)) in payments.iter_mut()
					{
						if *payment_hash == hashed {
							*preimage_option = Some(payment_preimage);
							*status = HTLCStatus::Succeeded;
							println!(
								"\nEVENT: successfully sent payment of {} satoshis from \
                                         payment hash {:?} with preimage {:?}",
								amt_sat,
								hex_utils::hex_str(&payment_hash.0),
								hex_utils::hex_str(&payment_preimage.0)
							);
							print!("> ");
							io::stdout().flush().unwrap();
						}
					}
				}
				Event::PaymentFailed { payment_hash, rejected_by_dest } => {
					print!(
						"\nEVENT: Failed to send payment to payment hash {:?}: ",
						hex_utils::hex_str(&payment_hash.0)
					);
					if rejected_by_dest {
						println!("rejected by destination node");
					} else {
						println!("route failed");
					}
					print!("> ");
					io::stdout().flush().unwrap();

					let mut payments = payment_storage.lock().unwrap();
					if payments.contains_key(&payment_hash) {
						let (_, _, ref mut status, _) = payments.get_mut(&payment_hash).unwrap();
						*status = HTLCStatus::Failed;
					}
				}
				Event::PendingHTLCsForwardable { time_forwardable } => {
					let forwarding_channel_manager = loop_channel_manager.clone();
					thread::spawn(move || {
						let min = time_forwardable.as_secs();
						if min > 0 {
							let seconds_to_sleep = thread_rng().gen_range(min, min * 5);
							thread::sleep(Duration::new(seconds_to_sleep, 0));
						}
						forwarding_channel_manager.process_pending_htlc_forwards();
					});
				}
				Event::SpendableOutputs { outputs } => {
					let destination_address = bitcoind_client.get_new_address();
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
			}
		}
		thread::sleep(Duration::new(1, 0));
	}
}