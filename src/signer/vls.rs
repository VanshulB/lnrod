//! Validating Lightning Signer integration

use crate::signer::keys::{DynSigner, InnerSign, PaymentSign, SpendableKeysInterface};
use anyhow::Result;
use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::{Address, Network, Script, Transaction, TxOut, WPubkeyHash};
use bitcoin::bech32::u5;
use bitcoin::hashes::Hash;
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey};
use bitcoin::util::psbt::serialize::Serialize;
use lightning::chain::keysinterface::{
	DelayedPaymentOutputDescriptor, KeysInterface, SpendableOutputDescriptor,
	StaticPaymentOutputDescriptor,
};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use lightning::util::ser::Writeable;
use lightning::chain::keysinterface::BaseSign;
use lightning_signer::lightning;
use lightning_signer::node::NodeConfig as SignerNodeConfig;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use std::any::Any;
use std::convert::TryFrom;
use std::fs;
use std::future::Future;
use std::io::Error;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::result::Result as StdResult;
use std::thread::current;
use bitcoin::hashes::hex::ToHex;
use lightning_signer::channel::ChannelId;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::util::INITIAL_COMMITMENT_NUMBER;
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use lightning_signer_server::server::remotesigner::{self, Basepoints, ChainParams, ChannelNonce, GetChannelBasepointsRequest, GetExtPubKeyRequest, GetPerCommitmentPointRequest, InitRequest, NewChannelRequest, NodeConfig, PingRequest, PubKey, ReadyChannelRequest, SignInvoiceRequest};
use lightning_signer_server::server::remotesigner::ready_channel_request::CommitmentType;
use lightning_signer_server::server::remotesigner::signer_client::SignerClient;
use log::info;
use rand::{Rng, thread_rng};
use tokio::{runtime, task};
use tokio::runtime::Builder;
use tonic::{Request, transport};
use tonic::transport::Channel;
use crate::chain::keysinterface::KeyMaterial;
use crate::{hex_utils, PaymentPreimage};
use crate::lightning::ln::chan_utils::{ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction, HolderCommitmentTransaction, HTLCOutputInCommitment};
use crate::lightning::ln::msgs::UnsignedChannelAnnouncement;

struct Adapter {
	inner: LoopbackSignerKeysInterface,
}

macro_rules! todo {
    () => {{
		println!("TODO");
		panic!("not yet implemented")
	}}
}

impl PaymentSign for LoopbackChannelSigner {
	#[allow(unused)]
	fn sign_counterparty_payment_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()> {
		todo!()
	}

	#[allow(unused)]
	fn sign_dynamic_p2wsh_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()> {
		todo!()
	}
}

impl InnerSign for LoopbackChannelSigner {
	fn box_clone(&self) -> Box<dyn InnerSign> {
		Box::new(self.clone())
	}

	fn as_any(&self) -> &dyn Any {
		self
	}

	fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), std::io::Error> {
		self.write(writer)
	}
}

impl KeysInterface for Adapter {
	type Signer = DynSigner;

	fn get_node_secret(&self) -> SecretKey {
		self.inner.get_node_secret()
	}

	fn get_destination_script(&self) -> Script {
		self.inner.get_destination_script()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		self.inner.get_shutdown_scriptpubkey()
	}

	fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
		let inner = self.inner.get_channel_signer(inbound, channel_value_satoshis);
		DynSigner { inner: Box::new(inner) }
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.inner.get_secure_random_bytes()
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		let inner = self.inner.read_chan_signer(reader)?;

		Ok(DynSigner::new(inner))
	}

	fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5]) -> Result<RecoverableSignature, ()> {
		self.inner.sign_invoice(hrp_bytes, invoice_data)
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inner.get_inbound_payment_key_material()
	}
}

impl SpendableKeysInterface for Adapter {
	/// Creates a Transaction which spends the given descriptors to the given outputs, plus an
	/// output to the given change destination (if sufficient change value remains). The
	/// transaction will have a feerate, at least, of the given value.
	///
	/// Returns `Err(())` if the output value is greater than the input value minus required fee or
	/// if a descriptor was duplicated.
	///
	/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
	///
	/// May panic if the `SpendableOutputDescriptor`s were not generated by Channels which used
	/// this KeysManager or one of the `DynSigner` created by this KeysManager.
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction> {
		self.inner
			.spend_spendable_outputs(
				descriptors,
				outputs,
				change_destination_script,
				feerate_sat_per_1000_weight,
				secp_ctx,
			)
			.map_err(|()| anyhow::anyhow!("failed in spend_spendable_outputs"))
	}
}

pub(crate) fn make_signer(network: Network, ldk_data_dir: String) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	let node_id_path = format!("{}/node_id", ldk_data_dir);
	let signer_path = format!("{}/signer", ldk_data_dir);
	let persister = Arc::new(KVJsonPersister::new(&signer_path));
	// FIXME use Node directly - requires rework of LoopbackSignerKeysInterface in the rls crate
	let validator_factory = Arc::new(SimpleValidatorFactory::new());
	let signer = MultiSigner::new_with_persister(persister, false, vec![], validator_factory);
	if let Ok(node_id_hex) = fs::read_to_string(node_id_path.clone()) {
		let node_id = PublicKey::from_str(&node_id_hex).unwrap();
		assert!(signer.get_node(&node_id).is_ok());

		let manager = LoopbackSignerKeysInterface { node_id, signer: Arc::new(signer) };
		Box::new(Adapter { inner: manager })
	} else {
		let node_config = SignerNodeConfig {
			network,
			key_derivation_style: KeyDerivationStyle::Native
		};
		let node_id = signer.new_node(node_config);
		fs::write(node_id_path, node_id.to_string()).expect("write node_id");
		let node = signer.get_node(&node_id).unwrap();

		let manager = LoopbackSignerKeysInterface { node_id, signer: Arc::new(signer) };

		let shutdown_scriptpubkey = manager.get_shutdown_scriptpubkey().into();
		let shutdown_address = Address::from_script(&shutdown_scriptpubkey, network)
			.expect("shutdown script must be convertible to address");
		info!("adding shutdown address {} to allowlist for {}", shutdown_address, hex_utils::hex_str(&node_id.serialize()));
		node.add_allowlist(&vec![shutdown_address.to_string()]).expect("add to allowlist");

		Box::new(Adapter { inner: manager })
	}
}

struct ClientAdapter {
	#[allow(unused)]
	runtime: runtime::Runtime,
	handle: runtime::Handle,
	client: Arc<Mutex<SignerClient<transport::Channel>>>,
	node_id: PublicKey,
	node_secret: SecretKey,
	xpub: ExtendedPubKey,
	key_material: KeyMaterial,
}

impl ClientAdapter {
	async fn new(mut client: SignerClient<Channel>, node_id: PublicKey, node_secret: SecretKey) -> ClientAdapter {
		let runtime = std::thread::spawn(|| {
			Builder::new_multi_thread().enable_all()
				.thread_name("vls-client")
				.worker_threads(2) // for debugging
				.build()
		}).join().expect("runtime join").expect("runtime");
		let handle = runtime.handle().clone();

		let xpub_request = Request::new(GetExtPubKeyRequest {
			node_id: Some(remotesigner::NodeId { data: node_id.serialize().to_vec() })
		});

		let response = client.get_ext_pub_key(xpub_request).await.expect("xpub call");
		let reply = response.into_inner();
		let xpub = ExtendedPubKey::from_str(&reply.xpub.expect("xpub").encoded).expect("xpub");

		let mut rng = rand::thread_rng();
		let mut key_material = [0; 32];
		rng.fill_bytes(&mut key_material);

		ClientAdapter {
			runtime,
			handle,
			client: Arc::new(Mutex::new(client)),
			node_id,
			node_secret,
			xpub,
			key_material: KeyMaterial(key_material),
		}
	}

	fn call_async<F: Future>(&self, f: F) -> F::Output {
		task::block_in_place(|| {
			println!("ENTER block_on {}", current().name().unwrap_or("?"));
			let res = self.handle.block_on(
				f
			);
			println!("EXIT block_on");
			res
		})
	}

	fn dest_wallet_path() -> Vec<ChildNumber> {
		vec![ChildNumber::from_normal_idx(1).expect("child number")]
	}

	fn proto_node_id(&self) -> Option<remotesigner::NodeId> {
		Some(self.node_id.into())
	}
}

#[derive(Clone)]
struct ClientSigner {
	handle: runtime::Handle,
	client: Arc<Mutex<SignerClient<transport::Channel>>>,
	node_id: PublicKey,
	channel_id: ChannelId,
	basepoints: ChannelPublicKeys,
	channel_value: u64,
}

#[allow(unused)]
impl KeysInterface for ClientAdapter {
	type Signer = DynSigner;

	fn get_node_secret(&self) -> SecretKey {
		self.node_secret
	}

	fn get_destination_script(&self) -> Script {
		let secp_ctx = Secp256k1::new();
		let xkey = self.xpub;
		let wallet_path = Self::dest_wallet_path();
		let pubkey = xkey.derive_pub(&secp_ctx, &wallet_path)
			.expect("derive")
			.public_key;
		Script::new_v0_wpkh(&WPubkeyHash::hash(&pubkey.serialize()))
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		// TODO review
		let mut client = self.client.lock().expect("lock");
		let response =
			self.call_async(client.ping(PingRequest { message: "hello".to_string() }))
				.expect("");
		let reply = response.into_inner();
		println!("XXX {}", reply.message);
		ShutdownScript::try_from(self.get_destination_script()).expect("script")
	}

	fn get_channel_signer(&self, _inbound: bool, channel_value: u64) -> Self::Signer {
		fn decode_pubkey(proto: Option<PubKey>) -> PublicKey {
			PublicKey::from_slice(&proto.expect("pubkey").data).expect("pubkey decode")
		}

		let mut channel_id_slice = [0u8; 32];
		thread_rng().fill_bytes(&mut channel_id_slice);
		let channel_nonce = Some(ChannelNonce { data: channel_id_slice.to_vec() });
		let channel_id = ChannelId(channel_id_slice);

		let mut client = self.client.lock().expect("lock");
		let response = self.call_async(
			client.new_channel(NewChannelRequest {
				node_id: self.proto_node_id(),
				channel_nonce0: channel_nonce.clone(),
			})).expect("call NewChannel");

		let reply = response.into_inner();
		println!("supplied nonce {} got nonce {}",
				 channel_id_slice.to_hex(),
				 reply.channel_nonce0.as_ref().unwrap().data.to_hex());

		let response = self.call_async(
			client.get_channel_basepoints(GetChannelBasepointsRequest {
				node_id: self.proto_node_id(),
				channel_nonce: channel_nonce.clone(),
			})).expect("call GetChannelBasepoints");
		let reply = response.into_inner();

		let bp = reply.basepoints.expect("basepoints");
		let basepoints = ChannelPublicKeys {
			funding_pubkey: decode_pubkey(bp.funding_pubkey),
			revocation_basepoint: decode_pubkey(bp.revocation),
			payment_point: decode_pubkey(bp.payment),
			delayed_payment_basepoint: decode_pubkey(bp.delayed_payment),
			htlc_basepoint: decode_pubkey(bp.htlc),
		};

		let signer = ClientSigner {
			handle: self.handle.clone(),
			client: self.client.clone(),
			node_id: self.node_id,
			channel_id,
			basepoints,
			channel_value,
		};
		DynSigner::new(signer)
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut rng = rand::thread_rng();
		let mut res = [0; 32];
		rng.fill_bytes(&mut res);
		res
	}

	fn read_chan_signer(&self, reader: &[u8]) -> StdResult<Self::Signer, DecodeError> {
		todo!()
	}

	fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5]) -> StdResult<RecoverableSignature, ()> {
		let mut client = self.client.lock().expect("lock");
		let response = self.call_async(
			client.sign_invoice(Request::new(SignInvoiceRequest {
				node_id: self.proto_node_id(),
				data_part: invoice_data.iter().map(|o| o.to_u8()).collect(),
				human_readable_part: String::from_utf8(hrp_bytes.to_vec()).expect("hrp"),
			}))).expect("call SignInvoiceRequest");
		let reply = response.into_inner();
		let mut sig = reply.signature.expect("signature").data;
		let rid_byte = sig.pop().expect("empty signature");
		let rid = RecoveryId::from_i32(rid_byte as i32).expect("rid");
		Ok(RecoverableSignature::from_compact(&sig, rid).expect("decode"))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.key_material
	}
}

#[allow(unused)]
impl SpendableKeysInterface for ClientAdapter {
	fn spend_spendable_outputs(&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>, change_destination_script: Script, feerate_sat_per_1000_weight: u32, secp_ctx: &Secp256k1<All>) -> Result<Transaction> {
		todo!()
	}
}

#[allow(unused)]
impl PaymentSign for ClientSigner {
	fn sign_counterparty_payment_input_t(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>) -> Result<Vec<Vec<u8>>, ()> {
		todo!()
	}

	fn sign_dynamic_p2wsh_input_t(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>) -> Result<Vec<Vec<u8>>, ()> {
		todo!()
	}
}

#[allow(unused)]
impl InnerSign for ClientSigner {
	fn box_clone(&self) -> Box<dyn InnerSign> {
		Box::new(self.clone())
	}

	fn as_any(&self) -> &dyn Any {
		self
	}

	fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), Error> {
		todo!()
	}
}

#[allow(unused)]
impl BaseSign for ClientSigner {
	fn get_per_commitment_point(&self, idx: u64, _secp_ctx: &Secp256k1<All>) -> PublicKey {
		let mut client = self.client.lock().expect("lock");

		let response = self.call_async(
			client.get_per_commitment_point(GetPerCommitmentPointRequest {
				node_id: self.proto_node_id(),
				channel_nonce: self.proto_channel_nonce(),
				n: INITIAL_COMMITMENT_NUMBER - idx
			})).expect("call SignInvoiceRequest");
		let reply = response.into_inner();
		PublicKey::from_slice(&reply.per_commitment_point.expect("point").data).expect("point decode")
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		todo!()
	}

	fn validate_holder_commitment(&self, holder_tx: &HolderCommitmentTransaction, preimages: Vec<PaymentPreimage>) -> StdResult<(), ()> {
		todo!()
	}

	fn pubkeys(&self) -> &ChannelPublicKeys {
		&self.basepoints
	}

	fn channel_keys_id(&self) -> [u8; 32] {
		todo!()
	}

	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<All>) -> StdResult<(Signature, Vec<Signature>), ()> {
		todo!()
	}

	fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> StdResult<(), ()> {
		todo!()
	}

	fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<All>) -> StdResult<(Signature, Vec<Signature>), ()> {
		todo!()
	}

	fn unsafe_sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<All>) -> StdResult<(Signature, Vec<Signature>), ()> {
		todo!()
	}

	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<All>) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_closing_transaction(&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<All>) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_channel_announcement(&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<All>) -> StdResult<(Signature, Signature), ()> {
		todo!()
	}

	fn ready_channel(&mut self, p: &ChannelTransactionParameters) {
		let mut client = self.client.lock().expect("lock");

		let cp_param = p.counterparty_parameters.as_ref().expect("cp param");
		let cp_keys = &cp_param.pubkeys;
		let cp_basepoints = Basepoints {
			revocation: Some(cp_keys.revocation_basepoint.into()),
			payment: Some(cp_keys.payment_point.into()),
			htlc: Some(cp_keys.htlc_basepoint.into()),
			delayed_payment: Some(cp_keys.delayed_payment_basepoint.into()),
			funding_pubkey: Some(cp_keys.funding_pubkey.into()),
		};
		let commitment_type = if p.opt_anchors.is_some() {
			CommitmentType::Anchors
		} else {
			CommitmentType::StaticRemotekey
		};
		let response = self.call_async(
			client.ready_channel(ReadyChannelRequest {
				node_id: self.proto_node_id(),
				channel_nonce0: self.proto_channel_nonce(),
				option_channel_nonce: None,
				is_outbound: p.is_outbound_from_holder,
				channel_value_sat: self.channel_value,
				push_value_msat: 0,
				funding_outpoint: p.funding_outpoint.map(|p| p.into()),
				holder_selected_contest_delay: p.holder_selected_contest_delay as u32,
				holder_shutdown_script: vec![],
				holder_shutdown_key_path: vec![],
				counterparty_basepoints: Some(cp_basepoints),
				counterparty_selected_contest_delay: cp_param.selected_contest_delay as u32,
				counterparty_shutdown_script: vec![],
				commitment_type: commitment_type as i32,
			})).expect("call SignInvoiceRequest");
		response.into_inner();
	}
}

impl ClientSigner {
	fn proto_node_id(&self) -> Option<remotesigner::NodeId> {
		Some(self.node_id.into())
	}

	fn proto_channel_nonce(&self) -> Option<remotesigner::ChannelNonce> {
		Some(self.channel_id.into())
	}

	fn call_async<F: Future>(&self, f: F) -> F::Output {
		task::block_in_place(|| {
			self.handle.block_on(f)
		})
	}
}

pub(crate) async fn make_remote_signer(network: Network, ldk_data_dir: String) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	let node_id_path = format!("{}/node_id", ldk_data_dir);
	let node_secret_path = format!("{}/node_secret", ldk_data_dir);

	if let Ok(node_id_hex) = fs::read_to_string(node_id_path.clone()) {
		let node_id = PublicKey::from_str(&node_id_hex).unwrap();
		let node_secret_hex = fs::read_to_string(node_secret_path.clone()).expect("node secret");
		let node_secret = SecretKey::from_str(&node_secret_hex).expect("node secret hex");
		let client = connect().await.expect("connect");
		let adapter = ClientAdapter::new(client, node_id, node_secret).await;
		Box::new(adapter)
	} else {
		let mut client = connect().await.expect("connect VLS");
		let init_request = Request::new(InitRequest {
			node_config: Some(NodeConfig { key_derivation_style: KeyDerivationStyle::Native as i32 }),
			chainparams: Some(ChainParams { network_name: network.to_string() }),
			coldstart: true,
			hsm_secret: None,
		});

		let response = client.init(init_request).await.expect("init");
		let reply = response.into_inner();
		let node_id_bytes = reply.node_id.expect("missing node_id").data;
		let node_secret_bytes = reply.node_secret.expect("missing node_secret").data;
		let node_id = PublicKey::from_slice(&node_id_bytes).expect("node_id as public key");
		let node_secret = SecretKey::from_slice(&node_secret_bytes).expect("node_secret as secret key");
		fs::write(node_secret_path, node_secret.to_string()).expect("write node_secret");
		fs::write(node_id_path, node_id.to_string()).expect("write node_id");
		let adapter = ClientAdapter::new(client, node_id, node_secret).await;
		Box::new(adapter)
	}
}
