//! Validating Lightning Signer integration

use crate::{hex_utils, DynSigner, InnerSign, PaymentPreimage, SpendableKeysInterface};
use anyhow::{anyhow, Result};
use bitcoin::bech32::u5;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey};
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::PublicKey as BitcoinPublicKey;
use bitcoin::{
	consensus, Address, Network, Script, SigHashType, Transaction, TxIn, TxOut, WPubkeyHash,
};
use lightning::chain::keysinterface::{BaseSign, KeyMaterial, Recipient};
use lightning::chain::keysinterface::{
	DelayedPaymentOutputDescriptor, KeysInterface, SpendableOutputDescriptor,
	StaticPaymentOutputDescriptor,
};
use lightning::ln::chan_utils::{
	ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
	HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::ln::script::ShutdownScript;
use lightning::util::ser::Writeable;
use lightning_signer::channel::ChannelId;
use lightning_signer::lightning;
use lightning_signer::node::NodeConfig as SignerNodeConfig;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::util::crypto_utils::bitcoin_vec_to_signature;
use lightning_signer::util::loopback::LoopbackSignerKeysInterface;
use lightning_signer::util::transaction_utils::MAX_VALUE_MSAT;
use lightning_signer::util::{transaction_utils, INITIAL_COMMITMENT_NUMBER};
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use lightning_signer_server::server::remotesigner::ready_channel_request::CommitmentType;
use lightning_signer_server::server::remotesigner::signer_client::SignerClient;
use lightning_signer_server::server::remotesigner::{
	self, AddAllowlistRequest, Basepoints, ChainParams, ChannelNonce, GetChannelBasepointsRequest,
	GetNodeParamRequest, GetPerCommitmentPointRequest, InitRequest, InputDescriptor, KeyLocator,
	NewChannelRequest, NodeConfig, OutputDescriptor, PingRequest, PubKey, ReadyChannelRequest,
	SignChannelAnnouncementRequest, SignCounterpartyCommitmentTxPhase2Request,
	SignHolderCommitmentTxPhase2Request, SignInvoiceRequest, SignMutualCloseTxPhase2Request,
	SignOnchainTxRequest, UnilateralCloseInfo, ValidateCounterpartyRevocationRequest,
	ValidateHolderCommitmentTxPhase2Request,
};
use log::{info, trace};
use rand::{thread_rng, Rng};
use std::any::Any;
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::io::Error;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::{runtime, task};
use tonic::{transport, Request, Response, Status};

struct Adapter {
	inner: LoopbackSignerKeysInterface,
	sweep_address: Address,
}

macro_rules! todo {
	() => {{
		println!("TODO");
		panic!("not yet implemented")
	}};
}

impl KeysInterface for Adapter {
	type Signer = DynSigner;

	fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
		self.inner.get_node_secret(recipient)
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

	fn sign_invoice(
		&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		self.inner.sign_invoice(hrp_bytes, invoice_data, recipient)
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inner.get_inbound_payment_key_material()
	}
}

impl SpendableKeysInterface for Adapter {
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction> {
		let tx = self
			.inner
			.spend_spendable_outputs(
				descriptors,
				outputs,
				change_destination_script,
				feerate_sat_per_1000_weight,
				secp_ctx,
			)
			.map_err(|()| anyhow::anyhow!("failed in spend_spendable_outputs"))?;
		info!("spend spendable {}", bitcoin::consensus::encode::serialize_hex(&tx));
		Ok(tx)
	}

	fn get_sweep_address(&self) -> Address {
		self.sweep_address.clone()
	}

	fn get_node_id(&self) -> PublicKey {
		self.inner.node_id
	}
}

pub(crate) fn make_signer(
	network: Network, ldk_data_dir: String, sweep_address: Address,
) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
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
		Box::new(Adapter { inner: manager, sweep_address })
	} else {
		let node_config =
			SignerNodeConfig { network, key_derivation_style: KeyDerivationStyle::Ldk };
		let node_id = signer.new_node(node_config);
		fs::write(node_id_path, node_id.to_string()).expect("write node_id");
		let node = signer.get_node(&node_id).unwrap();

		let manager = LoopbackSignerKeysInterface { node_id, signer: Arc::new(signer) };

		let shutdown_scriptpubkey = manager.get_shutdown_scriptpubkey().into();
		let shutdown_address = Address::from_script(&shutdown_scriptpubkey, network)
			.expect("shutdown script must be convertible to address");
		info!(
			"adding shutdown address {} to allowlist for {}",
			shutdown_address,
			hex_utils::hex_str(&node_id.serialize())
		);
		node.add_allowlist(&vec![shutdown_address.to_string()]).expect("add to allowlist");

		Box::new(Adapter { inner: manager, sweep_address })
	}
}

#[derive(Clone)]
struct ClientRunner {
	#[allow(unused)]
	runtime: Arc<runtime::Runtime>,
	handle: runtime::Handle,
	client: Arc<Mutex<SignerClient<transport::Channel>>>,
}

impl ClientRunner {
	fn new(vls_port: u16) -> Self {
		let runtime = std::thread::spawn(|| {
			runtime::Builder::new_multi_thread()
				.enable_all()
				.thread_name("vls-client")
				.worker_threads(2) // for debugging
				.build()
		})
		.join()
		.expect("runtime join")
		.expect("runtime");
		let handle = runtime.handle().clone();
		let join = handle.spawn_blocking(move || {
			runtime::Handle::current().block_on(connect(vls_port)).unwrap()
		});
		let client = task::block_in_place(|| runtime::Handle::current().block_on(join));

		ClientRunner {
			runtime: Arc::new(runtime),
			handle,
			client: Arc::new(Mutex::new(client.unwrap())),
		}
	}

	pub(crate) fn call<Q: 'static + Send, R: 'static + Send>(
		&self, request: Q,
		func: fn(
			Q,
			MutexGuard<SignerClient<transport::Channel>>,
			runtime::Handle,
		) -> Result<Response<R>, Status>,
	) -> Response<R> {
		trace!("call from {:?}", std::thread::current().name());
		let client = self.client.clone();
		let handle = self.handle.clone();
		let join = self.handle.spawn_blocking(move || {
			trace!("call ON {:?}", std::thread::current().name());
			let client = client.lock().unwrap();
			func(request, client, handle)
		});
		let response = task::block_in_place(|| self.handle.block_on(join).unwrap().unwrap());
		response
	}

	// pub(crate) fn call<Q: 'static + Send, R: 'static + Send, F: 'static + Send + Future<Output=Result<Response<R>, Status>>>(
	// 	&self,
	// 	request: Q,
	// 	func: fn(Q, MutexGuard<SignerClient<transport::Channel>>) -> F) -> Response<R>
	// {
	// 	let client = self.client.clone();
	// 	let join = self.handle.spawn_blocking(move || {
	// 		let client = client.lock().unwrap();
	// 		tokio::runtime::Handle::current().block_on(func(request, client))
	// 	});
	// 	let response =
	// 		task::block_in_place(|| {
	// 			tokio::runtime::Handle::current().block_on(join).unwrap().unwrap()
	// 		});
	// 	response
	// }
}

struct ClientAdapter {
	runner: ClientRunner,
	node_id: PublicKey,
	node_secret: SecretKey,
	xpub: ExtendedPubKey,
	key_material: KeyMaterial,
	sweep_address: Address,
}

impl ClientAdapter {
	async fn new(
		vls_port: u16, node_id: PublicKey, node_secret: SecretKey, sweep_address: Address,
	) -> ClientAdapter {
		let runner = ClientRunner::new(vls_port);

		let proto_node_id = Some(remotesigner::NodeId { data: node_id.serialize().to_vec() });

		let xpub_request = Request::new(GetNodeParamRequest { node_id: proto_node_id.clone() });
		let response =
			runner.call(xpub_request, |r, mut client, h| h.block_on(client.get_node_param(r)));
		let reply = response.into_inner();
		let xpub = ExtendedPubKey::from_str(&reply.xpub.expect("xpub").encoded).expect("xpub");

		let allowlist_request = AddAllowlistRequest {
			node_id: proto_node_id.clone(),
			addresses: vec![sweep_address.to_string()],
		};
		let response =
			runner.call(allowlist_request, |r, mut client, h| h.block_on(client.add_allowlist(r)));
		response.into_inner();

		let mut rng = rand::thread_rng();
		let mut key_material = [0; 32];
		rng.fill_bytes(&mut key_material);

		ClientAdapter {
			runner,
			node_id,
			node_secret,
			xpub,
			key_material: KeyMaterial(key_material),
			sweep_address,
		}
	}

	fn proto_node_id(&self) -> Option<remotesigner::NodeId> {
		Some(self.node_id.into())
	}

	fn get_destination_pubkey(&self) -> BitcoinPublicKey {
		let secp_ctx = Secp256k1::new();
		let xkey = self.xpub;
		let wallet_path: Vec<_> = dest_wallet_path()
			.into_iter()
			.map(|i| ChildNumber::from_normal_idx(i).unwrap())
			.collect();
		let pubkey = xkey.derive_pub(&secp_ctx, &wallet_path).expect("derive").public_key;
		pubkey
	}
}

fn dest_wallet_path() -> Vec<u32> {
	vec![1]
}

#[derive(Clone)]
struct ClientSigner {
	runner: ClientRunner,
	node_id: PublicKey,
	channel_id: ChannelId,
	basepoints: ChannelPublicKeys,
	channel_value: u64,
}

#[allow(unused)]
impl KeysInterface for ClientAdapter {
	type Signer = DynSigner;

	fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
		match recipient {
			Recipient::Node => Ok(self.node_secret),
			Recipient::PhantomNode => Err(()),
		}
	}

	fn get_destination_script(&self) -> Script {
		let pubkey = self.get_destination_pubkey();
		Script::new_v0_wpkh(&WPubkeyHash::hash(&pubkey.serialize()))
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		// TODO review
		let request = PingRequest { message: "hello".to_string() };
		let response = self.runner.call(request, |r, mut client, h| h.block_on(client.ping(r)));
		let reply = response.into_inner();
		ShutdownScript::try_from(self.get_destination_script()).expect("script")
	}

	fn get_channel_signer(&self, _inbound: bool, channel_value: u64) -> Self::Signer {
		info!("ENTER get_channel_signer");
		fn decode_pubkey(proto: Option<PubKey>) -> PublicKey {
			PublicKey::from_slice(&proto.expect("pubkey").data).expect("pubkey decode")
		}

		let mut channel_id_slice = [0u8; 32];
		thread_rng().fill_bytes(&mut channel_id_slice);
		let channel_id = ChannelId::new(&channel_id_slice);
		let channel_nonce = Some(ChannelNonce { data: channel_id.inner().clone() });

		let request = NewChannelRequest {
			node_id: self.proto_node_id(),
			channel_nonce0: channel_nonce.clone(),
		};
		let response =
			self.runner.call(request, |r, mut client, h| h.block_on(client.new_channel(r)));
		let reply = response.into_inner();
		println!(
			"supplied nonce {} got nonce {}",
			channel_id_slice.to_hex(),
			reply.channel_nonce0.as_ref().unwrap().data.to_hex()
		);

		let request = GetChannelBasepointsRequest {
			node_id: self.proto_node_id(),
			channel_nonce: channel_nonce.clone(),
		};

		let response = self
			.runner
			.call(request, |r, mut client, h| h.block_on(client.get_channel_basepoints(r)));
		let reply = response.into_inner();

		let bp = reply.basepoints.expect("basepoints");
		let basepoints = ChannelPublicKeys {
			funding_pubkey: decode_pubkey(bp.funding_pubkey),
			revocation_basepoint: decode_pubkey(bp.revocation),
			payment_point: decode_pubkey(bp.payment),
			delayed_payment_basepoint: decode_pubkey(bp.delayed_payment),
			htlc_basepoint: decode_pubkey(bp.htlc),
		};

		let runner = self.runner.clone();
		let signer =
			ClientSigner { runner, node_id: self.node_id, channel_id, basepoints, channel_value };
		info!("EXIT get_channel_signer");
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

	fn sign_invoice(
		&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient,
	) -> StdResult<RecoverableSignature, ()> {
		let request = SignInvoiceRequest {
			node_id: self.proto_node_id(),
			data_part: invoice_data.iter().map(|o| o.to_u8()).collect(),
			human_readable_part: String::from_utf8(hrp_bytes.to_vec()).expect("hrp"),
		};
		panic!()
		// let response = self.call_async( async {
		// 	let x = {
		// 		let mut client = client.lock().unwrap();
		// 		client.sign_invoice(Request::new(r))
		// 	};
		// 	x.await
		// }).expect("call SignInvoiceRequest");
		// let reply = response.into_inner();
		// let mut sig = reply.signature.expect("signature").data;
		// let rid_byte = sig.pop().expect("empty signature");
		// let rid = RecoveryId::from_i32(rid_byte as i32).expect("rid");
		// Ok(RecoverableSignature::from_compact(&sig, rid).expect("decode"))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.key_material
	}
}

#[allow(unused)]
impl SpendableKeysInterface for ClientAdapter {
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction> {
		info!("ENTER spend_spendable_outputs");
		let mut tx = create_spending_transaction(
			descriptors,
			outputs,
			change_destination_script,
			feerate_sat_per_1000_weight,
		)?;
		let mut input_descs = Vec::new();
		for desc in descriptors {
			let (
				revocation_pubkey,
				commitment_point,
				channel_keys_id,
				key_path,
				value_sat,
				spend_type,
			) = match desc {
				SpendableOutputDescriptor::StaticOutput { outpoint, output } => {
					if output.script_pubkey != self.get_destination_script() {
						unimplemented!("static output sweep is not our shutdown scriptpubkey")
					}
					let pubkey = self.get_destination_pubkey();
					let witness_script =
						bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
					(
						None,
						None,
						None,
						dest_wallet_path(),
						output.value,
						remotesigner::SpendType::P2wpkh,
					)
				}
				SpendableOutputDescriptor::DelayedPaymentOutput(d) => (
					Some(d.revocation_pubkey),
					Some(d.per_commitment_point),
					Some(d.channel_keys_id),
					vec![],
					d.output.value,
					remotesigner::SpendType::P2wsh,
				),
				SpendableOutputDescriptor::StaticPaymentOutput(d) => {
					// dynamic remote payment is legacy and unsupported, set per-commitment point to None
					(
						None,
						None,
						Some(d.channel_keys_id),
						vec![],
						d.output.value,
						remotesigner::SpendType::P2wpkh,
					)
				}
			};

			let key_loc = Some(KeyLocator {
				key_path,
				close_info: channel_keys_id.map(|cki| UnilateralCloseInfo {
					channel_nonce: Some(ChannelNonce { data: cki.to_vec() }),
					commitment_point: commitment_point.map(|p| p.into()),
					revocation_pubkey: revocation_pubkey.map(|k| k.into()),
				}),
			});
			let input_desc = InputDescriptor {
				key_loc,
				value_sat: value_sat as i64,
				spend_type: spend_type as i32,
				redeem_script: vec![],
			};
			input_descs.push(input_desc);
		}

		let output_descs = tx
			.output
			.iter()
			.map(|o| OutputDescriptor { key_loc: None, witscript: vec![] })
			.collect();

		let request = SignOnchainTxRequest {
			node_id: self.proto_node_id(),
			tx: Some(remotesigner::Transaction {
				raw_tx_bytes: consensus::encode::serialize(&tx),
				input_descs,
				output_descs,
			}),
		};
		let response =
			self.runner.call(request, |r, mut client, h| h.block_on(client.sign_onchain_tx(r)));
		let reply = response.into_inner();
		assert_eq!(reply.witnesses.len(), tx.input.len());
		for (idx, w) in reply.witnesses.into_iter().enumerate() {
			tx.input[idx].witness = w.stack;
		}
		Ok(tx)
	}

	fn get_sweep_address(&self) -> Address {
		self.sweep_address.clone()
	}

	fn get_node_id(&self) -> PublicKey {
		self.node_id
	}
}

pub fn create_spending_transaction(
	descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
	change_destination_script: Script, feerate_sat_per_1000_weight: u32,
) -> Result<Transaction> {
	let mut input = Vec::new();
	let mut input_value = 0;
	let mut witness_weight = 0;
	let mut output_set = HashSet::with_capacity(descriptors.len());
	for outp in descriptors {
		match outp {
			SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
				input.push(TxIn {
					previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
					script_sig: Script::new(),
					sequence: 0,
					witness: Vec::new(),
				});
				witness_weight += StaticPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
				input_value += descriptor.output.value;
				if !output_set.insert(descriptor.outpoint) {
					return Err(anyhow!("duplicate"));
				}
			}
			SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
				input.push(TxIn {
					previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
					script_sig: Script::new(),
					sequence: descriptor.to_self_delay as u32,
					witness: Vec::new(),
				});
				witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
				input_value += descriptor.output.value;
				if !output_set.insert(descriptor.outpoint) {
					return Err(anyhow!("duplicate"));
				}
			}
			SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
				input.push(TxIn {
					previous_output: outpoint.into_bitcoin_outpoint(),
					script_sig: Script::new(),
					sequence: 0,
					witness: Vec::new(),
				});
				witness_weight += 1 + 73 + 34;
				input_value += output.value;
				if !output_set.insert(*outpoint) {
					return Err(anyhow!("duplicate"));
				}
			}
		}
		if input_value > MAX_VALUE_MSAT / 1000 {
			return Err(anyhow!("overflow"));
		}
	}
	let mut spend_tx = Transaction { version: 2, lock_time: 0, input, output: outputs };
	transaction_utils::maybe_add_change_output(
		&mut spend_tx,
		input_value,
		witness_weight,
		feerate_sat_per_1000_weight,
		change_destination_script,
	)
	.map_err(|()| anyhow!("could not add change"))?;
	Ok(spend_tx)
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
		// FIXME
		Ok(())
	}
}

#[allow(unused)]
impl BaseSign for ClientSigner {
	fn get_per_commitment_point(&self, idx: u64, _secp_ctx: &Secp256k1<All>) -> PublicKey {
		let n = INITIAL_COMMITMENT_NUMBER - idx;
		info!("ENTER get_per_commitment_point {}", n);
		let request = GetPerCommitmentPointRequest {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			n,
			point_only: true,
		};
		let response = self
			.runner
			.call(request, |r, mut client, h| h.block_on(client.get_per_commitment_point(r)));
		let reply = response.into_inner();
		info!("EXIT get_per_commitment_point");
		PublicKey::from_slice(&reply.per_commitment_point.expect("point").data)
			.expect("point decode")
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		let n = 2 + INITIAL_COMMITMENT_NUMBER - idx;
		info!("ENTER release_commitment_secret {}", n - 2);
		let request = GetPerCommitmentPointRequest {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			n,
			point_only: false,
		};
		let response = self
			.runner
			.call(request, |r, mut client, h| h.block_on(client.get_per_commitment_point(r)));
		let reply = response.into_inner();
		info!("EXIT release_commitment_secret");
		reply.old_secret.expect("must have a secret").data.try_into().expect("length != 32")
	}

	fn validate_holder_commitment(
		&self, holder_tx: &HolderCommitmentTransaction, preimages: Vec<PaymentPreimage>,
	) -> StdResult<(), ()> {
		info!(
			"validate_holder_commitment {}",
			INITIAL_COMMITMENT_NUMBER - holder_tx.commitment_number()
		);
		let request = ValidateHolderCommitmentTxPhase2Request {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			commitment_info: Some((&*holder_tx.trust(), true).into()),
			commit_signature: Some(holder_tx.counterparty_sig.into()),
			htlc_signatures: holder_tx
				.counterparty_htlc_sigs
				.iter()
				.map(|s| s.clone().into())
				.collect(),
		};
		let response = self.runner.call(request, |r, mut client, h| {
			h.block_on(client.validate_holder_commitment_tx_phase2(r))
		});
		let reply = response.into_inner();
		// Ignore the reply (with revocation secret).
		// It's retrieved by LDK via release_commitment_secret.
		Ok(())
	}

	fn pubkeys(&self) -> &ChannelPublicKeys {
		&self.basepoints
	}

	fn channel_keys_id(&self) -> [u8; 32] {
		self.channel_id.as_slice().try_into().unwrap()
	}

	fn sign_counterparty_commitment(
		&self, commitment_tx: &CommitmentTransaction, preimages: Vec<PaymentPreimage>,
		secp_ctx: &Secp256k1<All>,
	) -> StdResult<(Signature, Vec<Signature>), ()> {
		info!("ENTER sign_counterparty_commitment");
		let request = SignCounterpartyCommitmentTxPhase2Request {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			commitment_info: Some((commitment_tx, false).into()),
		};
		let response = self.runner.call(request, |r, mut client, h| {
			h.block_on(client.sign_counterparty_commitment_tx_phase2(r))
		});
		let reply = response.into_inner();
		let sig =
			bitcoin_vec_to_signature(&reply.signature.as_ref().unwrap().data, SigHashType::All)
				.unwrap();
		// FIXME anchor sighashtype
		let htlc_sigs = reply
			.htlc_signatures
			.iter()
			.map(|s| bitcoin_vec_to_signature(&s.data, SigHashType::All).unwrap())
			.collect();

		info!("EXIT sign_counterparty_commitment");
		Ok((sig, htlc_sigs))
	}

	fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> StdResult<(), ()> {
		info!("ENTER validate_counterparty_revocation");
		let request = ValidateCounterpartyRevocationRequest {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			revoke_num: INITIAL_COMMITMENT_NUMBER - idx,
			old_secret: Some((*secret).into()),
		};
		let response = self.runner.call(request, |r, mut client, h| {
			h.block_on(client.validate_counterparty_revocation(r))
		});
		let _reply = response.into_inner();
		info!("EXIT validate_counterparty_revocation");
		Ok(())
	}

	fn sign_holder_commitment_and_htlcs(
		&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<All>,
	) -> StdResult<(Signature, Vec<Signature>), ()> {
		info!("ENTER sign_holder_commitment_and_htlcs");
		let commit_num = INITIAL_COMMITMENT_NUMBER - commitment_tx.commitment_number();
		let request = SignHolderCommitmentTxPhase2Request {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			commit_num,
		};
		let response = self.runner.call(request, |r, mut client, h| {
			h.block_on(client.sign_holder_commitment_tx_phase2(r))
		});
		let reply = response.into_inner();
		let sig =
			bitcoin_vec_to_signature(&reply.signature.as_ref().unwrap().data, SigHashType::All)
				.unwrap();
		// FIXME anchor sighashtype
		let htlc_sigs = reply
			.htlc_signatures
			.iter()
			.map(|s| bitcoin_vec_to_signature(&s.data, SigHashType::All).unwrap())
			.collect();

		info!("EXIT sign_holder_commitment_and_htlcs");
		Ok((sig, htlc_sigs))
	}

	fn unsafe_sign_holder_commitment_and_htlcs(
		&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<All>,
	) -> StdResult<(Signature, Vec<Signature>), ()> {
		unimplemented!("no unsafe signing in production")
	}

	fn sign_justice_revoked_output(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<All>,
	) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_justice_revoked_htlc(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_counterparty_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> StdResult<Signature, ()> {
		todo!()
	}

	fn sign_closing_transaction(
		&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<All>,
	) -> StdResult<Signature, ()> {
		let (node_id, channel_nonce) = self.proto_ids();

		let request = SignMutualCloseTxPhase2Request {
			node_id,
			channel_nonce,
			to_holder_value_sat: closing_tx.to_holder_value_sat(),
			to_counterparty_value_sat: closing_tx.to_counterparty_value_sat(),
			holder_shutdown_script: closing_tx.to_holder_script().clone().into_bytes(),
			counterparty_shutdown_script: closing_tx.to_counterparty_script().clone().into_bytes(),
			holder_wallet_path_hint: dest_wallet_path(),
		};
		let response = self
			.runner
			.call(request, |r, mut client, h| h.block_on(client.sign_mutual_close_tx_phase2(r)));
		let reply = response.into_inner();
		Ok(bitcoin_vec_to_signature(&reply.signature.expect("sig").data, SigHashType::All).unwrap())
	}

	fn sign_channel_announcement(
		&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<All>,
	) -> StdResult<(Signature, Signature), ()> {
		info!("sign channel announcement");
		let request = SignChannelAnnouncementRequest {
			node_id: self.proto_node_id(),
			channel_nonce: self.proto_channel_nonce(),
			channel_announcement: msg.encode(),
		};
		let response = self
			.runner
			.call(request, |r, mut client, h| h.block_on(client.sign_channel_announcement(r)));
		let reply = response.into_inner();
		Ok((
			reply.node_signature.expect("sig").try_into()?,
			reply.bitcoin_signature.expect("sig").try_into()?,
		))
	}

	fn ready_channel(&mut self, p: &ChannelTransactionParameters) {
		info!("ENTER ready_channel");
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
		let request = ReadyChannelRequest {
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
		};
		let response =
			self.runner.call(request, |r, mut client, h| h.block_on(client.ready_channel(r)));
		info!("EXIT ready_channel");
		response.into_inner();
	}
}

impl ClientSigner {
	fn proto_ids(&self) -> (Option<remotesigner::NodeId>, Option<remotesigner::ChannelNonce>) {
		(self.proto_node_id(), self.proto_channel_nonce())
	}

	fn proto_node_id(&self) -> Option<remotesigner::NodeId> {
		Some(self.node_id.into())
	}

	fn proto_channel_nonce(&self) -> Option<remotesigner::ChannelNonce> {
		Some(self.channel_id.clone().into())
	}
}

pub async fn connect(
	vls_port: u16,
) -> Result<SignerClient<transport::Channel>, Box<dyn std::error::Error>> {
	let endpoint = format!("http://127.0.0.1:{}", vls_port);
	Ok(SignerClient::connect(endpoint).await?)
}

pub(crate) async fn make_remote_signer(
	vls_port: u16, network: Network, ldk_data_dir: String, sweep_address: Address,
) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	setup_tokio_log();

	let node_id_path = format!("{}/node_id", ldk_data_dir);
	let node_secret_path = format!("{}/node_secret", ldk_data_dir);

	if let Ok(node_id_hex) = fs::read_to_string(node_id_path.clone()) {
		let node_id = PublicKey::from_str(&node_id_hex).unwrap();
		let node_secret_hex = fs::read_to_string(node_secret_path.clone()).expect("node secret");
		let node_secret = SecretKey::from_str(&node_secret_hex).expect("node secret hex");
		let adapter = ClientAdapter::new(vls_port, node_id, node_secret, sweep_address).await;
		Box::new(adapter)
	} else {
		let (node_id, node_secret) =
			do_init(vls_port, network, node_id_path, node_secret_path).await;

		let adapter = ClientAdapter::new(vls_port, node_id, node_secret, sweep_address).await;
		Box::new(adapter)
	}
}

async fn do_init(
	vls_port: u16, network: Network, node_id_path: String, node_secret_path: String,
) -> (PublicKey, SecretKey) {
	let init_request = Request::new(InitRequest {
		node_config: Some(NodeConfig { key_derivation_style: KeyDerivationStyle::Ldk as i32 }),
		chainparams: Some(ChainParams { network_name: network.to_string() }),
		coldstart: true,
		hsm_secret: None,
	});

	let mut client = connect(vls_port).await.expect("connect");
	let response = client.init(init_request).await.expect("init");
	let reply = response.into_inner();
	let node_id_bytes = reply.node_id.expect("missing node_id").data;

	let response = client
		.get_node_param(GetNodeParamRequest {
			node_id: Some(remotesigner::NodeId { data: node_id_bytes.clone() }),
		})
		.await
		.expect("param");
	let reply = response.into_inner();
	let node_secret_bytes = reply.node_secret.expect("missing node_secret").data;

	let node_id = PublicKey::from_slice(&node_id_bytes).expect("node_id as public key");
	let node_secret = SecretKey::from_slice(&node_secret_bytes).expect("node_secret as secret key");

	fs::write(node_secret_path, node_secret.to_string()).expect("write node_secret");
	fs::write(node_id_path, node_id.to_string()).expect("write node_id");
	(node_id, node_secret)
}

fn setup_tokio_log() {
	let subscriber =
		tracing_subscriber::FmtSubscriber::builder().with_max_level(tracing::Level::INFO).finish();

	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}
