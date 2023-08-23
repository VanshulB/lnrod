//! Validating Lightning Signer integration

use crate::{hex_utils, DynSigner, SpendableKeysInterface};
use bech32::u5;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::secp256k1::{ecdh::SharedSecret, All, PublicKey, Scalar, Secp256k1};
use bitcoin::{Address, Network, Script, Transaction, TxOut};
use lightning::chain::keysinterface::SpendableOutputDescriptor;
use lightning::chain::keysinterface::{KeyMaterial, Recipient};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use lightning_signer::bitcoin::secp256k1::ecdsa::Signature;
use lightning_signer::lightning::chain::keysinterface::{
	EntropySource, NodeSigner, SignerProvider,
};
use lightning_signer::lightning::ln::msgs::UnsignedGossipMessage;
use lightning_signer::node::NodeConfig as SignerNodeConfig;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::fs::FileSeedPersister;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::loopback::LoopbackSignerKeysInterface;
use lightning_signer::{bitcoin, lightning};
use log::info;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;
use vls_frontend::Frontend;
use vls_persist::kvv::redb::RedbKVVStore;
use vls_proxy::nodefront::SignerFront;
use vls_proxy::vls_frontend;
use vls_proxy::vls_frontend::frontend::SourceFactory;

struct Adapter {
	inner: LoopbackSignerKeysInterface,
	sweep_address: Address,
}

impl SignerProvider for Adapter {
	type Signer = DynSigner;

	fn generate_channel_keys_id(
		&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128,
	) -> [u8; 32] {
		self.inner.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
	}

	fn derive_channel_signer(
		&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32],
	) -> Self::Signer {
		let inner = self.inner.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		DynSigner { inner: Box::new(inner) }
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		let inner = self.inner.read_chan_signer(reader)?;

		Ok(DynSigner::new(inner))
	}

	fn get_destination_script(&self) -> Script {
		self.inner.get_destination_script()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		self.inner.get_shutdown_scriptpubkey()
	}
}

impl EntropySource for Adapter {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.inner.get_secure_random_bytes()
	}
}

impl NodeSigner for Adapter {
	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inner.get_inbound_payment_key_material()
	}

	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		match recipient {
			Recipient::Node => {}
			Recipient::PhantomNode => panic!("phantom node not supported"),
		}
		Ok(self.inner.node_id.clone())
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		self.inner.ecdh(recipient, other_key, tweak)
	}

	fn sign_invoice(
		&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		self.inner.sign_invoice(hrp_bytes, invoice_data, recipient)
	}

	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
		self.inner.sign_gossip_message(msg)
	}
}

impl SpendableKeysInterface for Adapter {
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		_secp_ctx: &Secp256k1<All>,
	) -> anyhow::Result<Transaction> {
		let tx = self
			.inner
			.spend_spendable_outputs(
				descriptors,
				outputs,
				change_destination_script,
				feerate_sat_per_1000_weight,
			)
			.map_err(|()| anyhow::anyhow!("failed in spend_spendable_outputs"))?;
		info!("spend spendable {}", bitcoin::consensus::encode::serialize_hex(&tx));
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

pub(crate) fn make_signer(
	network: Network, ldk_data_dir: String, sweep_address: Address, bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	let node_id_path = format!("{}/node_id", ldk_data_dir);
	let signer_path = format!("{}/signer", ldk_data_dir);
	let persister = Arc::new(RedbKVVStore::new(&signer_path));
	let seed_persister = Arc::new(FileSeedPersister::new(&signer_path));
	let validator_factory = Arc::new(SimpleValidatorFactory::new());
	let starting_time_factory = ClockStartingTimeFactory::new();
	let clock = Arc::new(StandardClock());
	let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
	// FIXME use Node directly - requires rework of LoopbackSignerKeysInterface in the rls crate
	let signer = Arc::new(MultiSigner::new(services));

	let source_factory = Arc::new(SourceFactory::new(ldk_data_dir, network));
	let frontend = Frontend::new(
		Arc::new(SignerFront { signer: Arc::clone(&signer), external_persist: None }),
		source_factory,
		bitcoin_rpc_url,
	);
	frontend.start();

	if let Ok(node_id_hex) = fs::read_to_string(node_id_path.clone()) {
		let node_id = PublicKey::from_str(&node_id_hex).unwrap();
		assert!(signer.get_node(&node_id).is_ok());

		let manager = LoopbackSignerKeysInterface { node_id, signer };
		Box::new(Adapter { inner: manager, sweep_address })
	} else {
		let node_config = SignerNodeConfig {
			network,
			key_derivation_style: KeyDerivationStyle::Ldk,
			use_checkpoints: true,
		};
		let (node_id, _seed) = signer.new_node(node_config, seed_persister).unwrap();
		fs::write(node_id_path, node_id.to_string()).expect("write node_id");
		let node = signer.get_node(&node_id).unwrap();

		let manager = LoopbackSignerKeysInterface { node_id, signer };

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
