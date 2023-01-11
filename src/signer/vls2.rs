use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use bech32::u5;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::{
	ecdh::SharedSecret, ecdsa::RecoverableSignature, All, PublicKey, Scalar, Secp256k1, SecretKey,
};
use bitcoin::{Address, Network, Script, Transaction, TxOut};
use lightning::chain::keysinterface::{
	KeyMaterial, KeysInterface, Recipient, SpendableOutputDescriptor,
};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::DummyPersister;
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::{bitcoin, lightning};
use log::{debug, error, info};
use tokio::runtime::Handle;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::task;
use url::Url;
use vls_protocol_client::{ClientResult, Error, KeysManagerClient, Transport};
use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs::{self, DeBolt, SerBolt};
use vls_protocol_signer::vls_protocol::serde_bolt::WireString;
use vls_proxy::grpc::adapter::{ChannelRequest, ClientId, HsmdService};
use vls_proxy::grpc::incoming::TcpIncoming;
use vls_proxy::portfront::SignerPortFront;
use vls_proxy::vls_frontend::Frontend;
use vls_proxy::vls_protocol_client;
use vls_proxy::vls_protocol_client::SignerPort;
use vls_proxy::vls_protocol_signer;

use crate::bitcoin::Witness;
use crate::signer::util::create_spending_transaction;
use crate::util::Shutter;
use crate::{DynSigner, SpendableKeysInterface};

// A VLS client with a null transport.
// Actually runs VLS in-process, but still performs the protocol.
// No persistence.
struct NullTransport {
	handler: RootHandler,
}

impl NullTransport {
	pub fn new(address: Address) -> Self {
		let persister = Arc::new(DummyPersister);
		let allowlist = vec![address.to_string()];
		info!("allowlist {:?}", allowlist);
		let network = Network::Regtest; // TODO - get from config, env or args
		let policy = make_simple_policy(network);
		let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
		let starting_time_factory = ClockStartingTimeFactory::new();
		let clock = Arc::new(StandardClock());
		let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
		let seed = generate_seed();
		let builder = RootHandlerBuilder::new(network, 0, services, seed).allowlist(allowlist);
		let (handler, _) = builder.build();
		NullTransport { handler }
	}
}

impl Transport for NullTransport {
	fn node_call(&self, message_ser: Vec<u8>) -> ClientResult<Vec<u8>> {
		let message = msgs::from_vec(message_ser)?;
		debug!("ENTER node_call {:?}", message);
		let (result, _) = self.handler.handle(message).map_err(|e| {
			error!("error in handle: {:?}", e);
			Error::TransportError
		})?;
		debug!("REPLY node_call {:?}", result);
		Ok(result.as_vec())
	}

	fn call(&self, dbid: u64, peer_id: PubKey, message_ser: Vec<u8>) -> ClientResult<Vec<u8>> {
		let message = msgs::from_vec(message_ser)?;
		debug!("ENTER call({}) {:?}", dbid, message);
		let handler = self.handler.for_new_client(0, peer_id, dbid);
		let (result, _) = handler.handle(message).map_err(|e| {
			error!("error in handle: {:?}", e);
			Error::TransportError
		})?;
		debug!("REPLY call({}) {:?}", dbid, result);
		Ok(result.as_vec())
	}
}

struct TransportSignerPort {
	transport: Arc<dyn Transport>,
}

#[async_trait]
impl SignerPort for TransportSignerPort {
	async fn handle_message(&self, message: Vec<u8>) -> ClientResult<Vec<u8>> {
		self.transport.node_call(message)
	}

	fn clone(&self) -> Box<dyn SignerPort> {
		Box::new(TransportSignerPort { transport: self.transport.clone() })
	}
}

struct KeysManager {
	client: KeysManagerClient,
	sweep_address: Address,
}

impl KeysInterface for KeysManager {
	type Signer = DynSigner;

	fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
		self.client.get_node_secret(recipient)
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		self.client.ecdh(recipient, other_key, tweak)
	}

	fn get_destination_script(&self) -> Script {
		self.client.get_destination_script()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		self.client.get_shutdown_scriptpubkey()
	}

	fn generate_channel_keys_id(
		&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128,
	) -> [u8; 32] {
		self.client.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
	}

	fn derive_channel_signer(
		&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32],
	) -> Self::Signer {
		let client = self.client.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		DynSigner::new(client)
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.client.get_secure_random_bytes()
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		let signer = self.client.read_chan_signer(reader)?;
		Ok(DynSigner::new(signer))
	}

	fn sign_invoice(
		&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		self.client.sign_invoice(hrp_bytes, invoice_data, recipient)
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.client.get_inbound_payment_key_material()
	}
}

impl SpendableKeysInterface for KeysManager {
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		_secp_ctx: &Secp256k1<All>,
	) -> anyhow::Result<Transaction> {
		info!("ENTER spend_spendable_outputs");
		let mut tx = create_spending_transaction(
			descriptors,
			outputs,
			change_destination_script,
			feerate_sat_per_1000_weight,
		)?;
		let witnesses = self.client.sign_onchain_tx(&tx, descriptors);
		assert_eq!(witnesses.len(), tx.input.len());
		for (idx, w) in witnesses.into_iter().enumerate() {
			tx.input[idx].witness = Witness::from_vec(w);
		}
		Ok(tx)
	}

	fn get_sweep_address(&self) -> Address {
		self.sweep_address.clone()
	}

	fn sign_from_wallet(
		&self, _psbt: &PartiallySignedTransaction, _derivations: Vec<u32>,
	) -> PartiallySignedTransaction {
		unimplemented!("TODO")
	}
}

pub(crate) async fn make_null_signer(
	network: Network, ldk_data_dir: String, sweep_address: Address, bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	let node_id_path = format!("{}/node_id", ldk_data_dir);

	if let Ok(_node_id_hex) = fs::read_to_string(node_id_path.clone()) {
		unimplemented!("read from disk {}", node_id_path);
	} else {
		let transport = Arc::new(NullTransport::new(sweep_address.clone()));

		let signer_port = Box::new(TransportSignerPort { transport: transport.clone() });
		let frontend =
			Frontend::new(Arc::new(SignerPortFront { signer_port, network }), bitcoin_rpc_url);
		frontend.start();

		let node_id = transport.handler.node().get_id();
		let client = KeysManagerClient::new(transport, network.to_string());
		let keys_manager = KeysManager { client, sweep_address };
		fs::write(node_id_path, node_id.to_string()).expect("write node_id");
		Box::new(keys_manager)
	}
}

struct GrpcTransport {
	sender: Sender<ChannelRequest>,
	#[allow(unused)]
	node_secret: SecretKey,
	node_id: PublicKey,
	handle: Handle,
}

impl GrpcTransport {
	async fn new(
		network: Network, sender: Sender<ChannelRequest>, sweep_address: Address,
	) -> ClientResult<Self> {
		info!("waiting for signer");
		let init = msgs::HsmdInit2 {
			derivation_style: 0,
			network_name: WireString(network.to_string().into_bytes()),
			dev_seed: None,
			dev_allowlist: vec![WireString(sweep_address.to_string().into_bytes())],
		};
		let init_reply_vec = Self::do_call_async(sender.clone(), init.as_vec(), None).await?;
		let init_reply = msgs::HsmdInit2Reply::from_vec(init_reply_vec)?;
		let node_secret = SecretKey::from_slice(&init_reply.node_secret.0).expect("node secret");
		let secp_ctx = Secp256k1::new();
		let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret);
		let handle = Handle::current();

		info!("signer connected, node ID {}", node_id);
		Ok(Self { sender, node_secret, node_id, handle })
	}

	fn node_id(&self) -> PublicKey {
		self.node_id
	}

	fn do_call(
		handle: &Handle, sender: Sender<ChannelRequest>, message: Vec<u8>,
		client_id: Option<ClientId>,
	) -> ClientResult<Vec<u8>> {
		let join = handle.spawn_blocking(move || {
			Handle::current().block_on(Self::do_call_async(sender, message, client_id)).unwrap()
		});
		let result = task::block_in_place(|| handle.block_on(join)).expect("join");
		Ok(result)
	}

	async fn do_call_async(
		sender: Sender<ChannelRequest>, message: Vec<u8>, client_id: Option<ClientId>,
	) -> ClientResult<Vec<u8>> {
		// Create a one-shot channel to receive the reply
		let (reply_tx, reply_rx) = oneshot::channel();

		// Send a request to the gRPC handler to send to signer
		let request = ChannelRequest { client_id, message, reply_tx };

		// This can fail if gRPC adapter shut down
		sender.send(request).await.map_err(|_| Error::TransportError)?;
		let reply = reply_rx.await.map_err(|_| Error::TransportError)?;
		Ok(reply.reply)
	}
}

impl Transport for GrpcTransport {
	fn node_call(&self, message: Vec<u8>) -> ClientResult<Vec<u8>> {
		Self::do_call(&self.handle, self.sender.clone(), message, None)
	}

	fn call(&self, dbid: u64, peer_id: PubKey, message: Vec<u8>) -> ClientResult<Vec<u8>> {
		let client_id = Some(ClientId { peer_id: peer_id.0, dbid });

		Self::do_call(&self.handle, self.sender.clone(), message, client_id)
	}
}

pub(crate) async fn make_grpc_signer(
	shutter: Shutter, signer_handle: Handle, vls_port: u16, network: Network, ldk_data_dir: String,
	sweep_address: Address, bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	let node_id_path = format!("{}/node_id", ldk_data_dir);
	let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, vls_port));
	let incoming = TcpIncoming::new(addr, false, None).expect("listen incoming");

	let server = HsmdService::new(shutter.trigger.clone(), shutter.signal.clone());

	let sender = server.sender();

	signer_handle.spawn(server.start(incoming, shutter.signal));

	let transport = Arc::new(
		signer_handle
			.spawn(GrpcTransport::new(network, sender, sweep_address.clone()))
			.await
			.expect("join")
			.expect("gRPC transport init"),
	);
	let node_id = transport.node_id();

	let signer_port = Box::new(TransportSignerPort { transport: transport.clone() });
	let frontend =
		Frontend::new(Arc::new(SignerPortFront { signer_port, network }), bitcoin_rpc_url);
	frontend.start();

	let client = KeysManagerClient::new(transport, network.to_string());
	let keys_manager = KeysManager { client, sweep_address };
	fs::write(node_id_path, node_id.to_string()).expect("write node_id");

	Box::new(keys_manager)
}
