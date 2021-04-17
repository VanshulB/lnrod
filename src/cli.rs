#![allow(unused_imports)]

use crate::disk;
use crate::hex_utils;
use crate::{
	ChannelManager, FilesystemLogger, HTLCDirection, HTLCStatus, PaymentInfoStorage, PeerManager,
	MilliSatoshiAmount,
};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};
use bitcoin::secp256k1::Secp256k1;
use lightning::chain;
use lightning::ln::channelmanager::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::features::InvoiceFeatures;
use lightning::routing::network_graph::NetGraphMsgHandler;
use lightning::routing::router;
use lightning::util::config::UserConfig;
use rand;
use rand::Rng;
use std::io;
use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpStream};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct LdkUserInfo {
	pub bitcoind_rpc_username: String,
	pub bitcoind_rpc_password: String,
	pub bitcoind_rpc_port: u16,
	pub bitcoind_rpc_host: String,
	pub ldk_storage_dir_path: String,
	pub ldk_peer_listening_port: u16,
	pub network: Network,
}

pub(crate) fn poll_for_user_input(
	peer_manager: Arc<PeerManager>, channel_manager: Arc<ChannelManager>,
	router: Arc<NetGraphMsgHandler<Arc<dyn chain::Access>, Arc<FilesystemLogger>>>,
	payment_storage: PaymentInfoStorage, node_privkey: SecretKey, event_notifier: mpsc::Sender<()>,
	ldk_data_dir: String, logger: Arc<FilesystemLogger>, runtime_handle: Handle, network: Network,
) {
	println!("LDK startup successful. To view available commands: \"help\".\nLDK logs are available at <your-supplied-ldk-data-dir-path>/.ldk/logs");
	let stdin = io::stdin();
	print!("> ");
	io::stdout().flush().unwrap(); // Without flushing, the `>` doesn't print
	for line in stdin.lock().lines() {
		let _ = event_notifier.try_send(());
		let line = line.unwrap();
		let mut words = line.split_whitespace();
		if let Some(word) = words.next() {
			match word {
				"listpayments" => list_payments(payment_storage.clone()),
				"closechannel" => {
					let channel_id_str = words.next();
					if channel_id_str.is_none() {
						println!("ERROR: closechannel requires a channel ID: `closechannel <channel_id>`");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
					if channel_id_vec.is_none() {
						println!("ERROR: couldn't parse channel_id as hex");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let mut channel_id = [0; 32];
					channel_id.copy_from_slice(&channel_id_vec.unwrap());
					close_channel(channel_id, channel_manager.clone());
				}
				"forceclosechannel" => {
					let channel_id_str = words.next();
					if channel_id_str.is_none() {
						println!("ERROR: forceclosechannel requires a channel ID: `forceclosechannel <channel_id>`");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let channel_id_vec = hex_utils::to_vec(channel_id_str.unwrap());
					if channel_id_vec.is_none() {
						println!("ERROR: couldn't parse channel_id as hex");
						print!("> ");
						io::stdout().flush().unwrap();
						continue;
					}
					let mut channel_id = [0; 32];
					channel_id.copy_from_slice(&channel_id_vec.unwrap());
					force_close_channel(channel_id, channel_manager.clone());
				}
				_ => println!("Unknown command. See `\"help\" for available commands."),
			}
		}
		print!("> ");
		io::stdout().flush().unwrap();
	}
}

fn list_payments(payment_storage: PaymentInfoStorage) {
	let payments = payment_storage.lock().unwrap();
	print!("[");
	for (payment_hash, payment_info) in payments.deref() {
		let direction_str = match payment_info.1 {
			HTLCDirection::Inbound => "inbound",
			HTLCDirection::Outbound => "outbound",
		};
		println!("");
		println!("\t{{");
		println!("\t\tamount_satoshis: {},", payment_info.3);
		println!("\t\tpayment_hash: {},", hex_utils::hex_str(&payment_hash.0));
		println!("\t\thtlc_direction: {},", direction_str);
		println!(
			"\t\thtlc_status: {},",
			match payment_info.2 {
				HTLCStatus::Pending => "pending",
				HTLCStatus::Succeeded => "succeeded",
				HTLCStatus::Failed => "failed",
			}
		);

		println!("\t}},");
	}
	println!("]");
}

fn close_channel(channel_id: [u8; 32], channel_manager: Arc<ChannelManager>) {
	match channel_manager.close_channel(&channel_id) {
		Ok(()) => println!("EVENT: initiating channel close"),
		Err(e) => println!("ERROR: failed to close channel: {:?}", e),
	}
}

fn force_close_channel(channel_id: [u8; 32], channel_manager: Arc<ChannelManager>) {
	match channel_manager.force_close_channel(&channel_id) {
		Ok(()) => println!("EVENT: initiating channel force-close"),
		Err(e) => println!("ERROR: failed to force-close channel: {:?}", e),
	}
}
