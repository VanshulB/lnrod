use std::collections::HashMap;
use std::convert::TryInto;
use std::iter::FromIterator;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bitcoin::{Amount, Block, BlockHash};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::address::Address;
use bitcoin::util::psbt::serialize::Serialize;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::{AsyncBlockSourceResult, BlockHeaderData, BlockSource};
use lightning_block_sync::http::JsonResponse;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::convert::{BlockchainInfo, FundedTx, RawTx, SignedTx};
use jsonrpc_async::Client;
use jsonrpc_async::simple_http::SimpleHttpTransport;
use std::result;
use bitcoin::hashes::hex::ToHex;

#[derive(Clone)]
pub struct BitcoindClient {
	rpc: Arc<Mutex<Client>>,
	host: String,
	port: u16,
	fees: Arc<HashMap<Target, AtomicU32>>,
}


#[derive(Clone, Eq, Hash, PartialEq)]
pub enum Target {
	Background,
	Normal,
	HighPriority,
}

#[derive(Debug)]
pub enum Error {
	JsonRpc(jsonrpc_async::error::Error),
	Json(serde_json::error::Error),
	Io(std::io::Error),
}

impl From<jsonrpc_async::error::Error> for Error {
	fn from(e: jsonrpc_async::error::Error) -> Error {
		Error::JsonRpc(e)
	}
}

impl From<serde_json::error::Error> for Error {
	fn from(e: serde_json::error::Error) -> Error {
		Error::Json(e)
	}
}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Error {
		Error::Io(e)
	}
}

pub type Result<T> = result::Result<T, Error>;

impl BitcoindClient {
	pub async fn new(host: String, port: u16,
					 rpc_user: String, rpc_password: String) -> std::io::Result<Self> {
		let url = format!("http://{}:{}", host, port);
		let mut builder = SimpleHttpTransport::builder().url(&url).await.unwrap();
		builder = builder.auth(rpc_user, Some(rpc_password));
		let rpc = Client::with_transport(builder.build());

		let mut fees: HashMap<Target, AtomicU32> = HashMap::new();
		fees.insert(Target::Background, AtomicU32::new(253));
		fees.insert(Target::Normal, AtomicU32::new(2000));
		fees.insert(Target::HighPriority, AtomicU32::new(5000));

		let client = Self {
			rpc: Arc::new(Mutex::new(rpc)),
			host,
			port,
			fees: Arc::new(fees)
		};
		Ok(client)
	}

	pub async fn create_raw_transaction(&self, outputs: HashMap<String, u64>) -> RawTx {
		let outs_converted = serde_json::to_value([serde_json::Map::from_iter(
			outputs.iter().map(|(k, v)| (k.clone(), serde_json::Value::from(Amount::from_sat(*v).as_btc()))),
		)]).unwrap();

		self.call_into("createrawtransaction", &vec![json!([]), outs_converted]).await.unwrap()
	}

	pub async fn fund_raw_transaction(&self, raw_tx: RawTx) -> FundedTx {
		self.call_into("fundrawtransaction", &vec![json!(raw_tx.0)]).await.unwrap()
	}

	pub async fn sign_raw_transaction_with_wallet(&self, tx_hex: String) -> SignedTx {
		self.call_into("signrawtransactionwithwallet", &vec![json!(tx_hex)]).await.unwrap()
	}

	pub async fn get_new_address(&self) -> Address {
		let addr: String = self.call("getnewaddress", &vec![]).await.unwrap();
		Address::from_str(addr.as_str()).unwrap()
	}

	pub async fn get_blockchain_info(&self) -> BlockchainInfo {
		self.call_into("getblockchaininfo", &[]).await.unwrap()
	}

	async fn call<T: for<'a> serde::de::Deserialize<'a>>(
		&self,
		cmd: &str,
		args: &[serde_json::Value],
	) -> Result<T> {
		let rpc = self.rpc.lock().await;
		let v_args : Vec<_> = args.iter().map(serde_json::value::to_raw_value).collect::<std::result::Result<_,serde_json::Error>>()?;
		let req = rpc.build_request(cmd, &v_args[..]);
		// if log_enabled!(Debug) {
		// 	debug!(target: "bitcoincore_rpc", "JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));
		// }

		let resp = rpc.send_request(req).await.map_err(Error::from);
		// log_response(cmd, &resp);
		Ok(resp?.result()?)
	}

	async fn call_into<T>(&self, cmd: &str, args: &[serde_json::Value]) -> Result<T>
		where JsonResponse: TryInto<T, Error=std::io::Error> {
		let value: Value = self.call(cmd, args).await?;
		Ok(JsonResponse(value).try_into()?)
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
		let rpc = Arc::clone(&self.rpc);
		let ser = hex::encode(tx.serialize());
		tokio::spawn(async move {
			let rpc = rpc.lock().await;
			let raw_args = [serde_json::value::to_raw_value(&json![ser]).unwrap()];
			let req = rpc.build_request("sendrawtransaction", &raw_args);

			let txid: String = rpc.send_request(req).await.map_err(Error::from).unwrap().result().unwrap();
			println!("broadcast {}", txid);
		});
	}
}

impl BlockSource for BitcoindClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			Ok(self.call_into("getblockheader", &[json!(header_hash.to_hex())]).await.unwrap())
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			Ok(self.call_into("getblock", &[json!(header_hash.to_hex()), json!(0)]).await.unwrap())
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'_, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			let info = self.get_blockchain_info().await;
			Ok((info.latest_blockhash, Some(info.latest_height as u32)))
		})
	}
}
