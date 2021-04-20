use crate::convert::{BlockchainInfo, FundedTx, NewAddress, RawTx, SignedTx};
use base64;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::util::address::Address;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::http::HttpEndpoint;
use lightning_block_sync::rpc::RpcClient;
use serde_json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;

pub struct BitcoindClient {
	bitcoind_rpc_client: Arc<Mutex<RpcClient>>,
	host: String,
	port: u16,
	rpc_user: String,
	rpc_password: String,
	fees: Arc<HashMap<Target, AtomicU32>>,
}


#[derive(Clone, Eq, Hash, PartialEq)]
pub enum Target {
	Background,
	Normal,
	HighPriority,
}

impl BitcoindClient {
	pub fn new(host: String, port: u16,
			   rpc_user: String, rpc_password: String) -> std::io::Result<Self> {
		let http_endpoint = HttpEndpoint::for_host(host.clone()).with_port(port);
		let rpc_credentials =
			base64::encode(format!("{}:{}", rpc_user.clone(), rpc_password.clone()));
		let bitcoind_rpc_client = RpcClient::new(&rpc_credentials, http_endpoint)?;

		let mut fees: HashMap<Target, AtomicU32> = HashMap::new();
		fees.insert(Target::Background, AtomicU32::new(253));
		fees.insert(Target::Normal, AtomicU32::new(2000));
		fees.insert(Target::HighPriority, AtomicU32::new(5000));

		let client = Self {
			bitcoind_rpc_client: Arc::new(Mutex::new(bitcoind_rpc_client)),
			host,
			port,
			rpc_user,
			rpc_password,
			fees: Arc::new(fees)
		};
		Ok(client)
	}

	pub async fn get_new_rpc_client(&self) -> std::io::Result<RpcClient> {
		let http_endpoint = HttpEndpoint::for_host(self.host.clone()).with_port(self.port);
		let rpc_credentials =
			base64::encode(format!("{}:{}", self.rpc_user.clone(), self.rpc_password.clone()));
		RpcClient::new(&rpc_credentials, http_endpoint)
	}

	pub async fn create_raw_transaction(&self, outputs: Vec<HashMap<String, f64>>) -> RawTx {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let outputs_json = serde_json::json!(outputs);
		rpc.call_method::<RawTx>(
				"createrawtransaction",
				&vec![serde_json::json!([]), outputs_json],
			).await.unwrap()
	}

	pub async fn fund_raw_transaction(&self, raw_tx: RawTx) -> FundedTx {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let raw_tx_json = serde_json::json!(raw_tx.0);
		rpc.call_method("fundrawtransaction", &[raw_tx_json]).await.unwrap()
	}

	pub async fn sign_raw_transaction_with_wallet(&self, tx_hex: String) -> SignedTx {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let tx_hex_json = serde_json::json!(tx_hex);
		rpc.call_method("signrawtransactionwithwallet", &vec![tx_hex_json]).await.unwrap()
	}

	pub async fn get_new_address(&self) -> Address {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let addr_args = vec![serde_json::json!("LDK output address")];
		let addr = rpc.call_method::<NewAddress>("getnewaddress", &addr_args)
			.await.unwrap();
		Address::from_str(addr.0.as_str()).unwrap()
	}

	pub async fn get_blockchain_info(&self) -> BlockchainInfo {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		rpc.call_method::<BlockchainInfo>("getblockchaininfo", &vec![]).await.unwrap()
	}
}

impl FeeEstimator for BitcoindClient {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
		match confirmation_target {
			ConfirmationTarget::Background => {
				self.fees.get(&Target::Background).unwrap().load(Ordering::Acquire)
			}
			ConfirmationTarget::Normal => {
				self.fees.get(&Target::Normal).unwrap().load(Ordering::Acquire)
			}
			ConfirmationTarget::HighPriority => {
				self.fees.get(&Target::HighPriority).unwrap().load(Ordering::Acquire)
			}
		}
	}
}

impl BroadcasterInterface for BitcoindClient {
	fn broadcast_transaction(&self, tx: &Transaction) {
		let bitcoind_rpc_client = self.bitcoind_rpc_client.clone();
		let tx_serialized = serde_json::json!(encode::serialize_hex(tx));
		tokio::spawn(async move {
			let mut rpc = bitcoind_rpc_client.lock().await;
			rpc.call_method::<RawTx>("sendrawtransaction", &vec![tx_serialized]).await.unwrap();
		});
	}
}