use std::any::Any;
use std::fs;
use std::fs::File;
use std::io::Write;

use anyhow::Result;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::{Network, Transaction};
use lightning::chain::keysinterface::{
	DelayedPaymentOutputDescriptor, InMemorySigner, StaticPaymentOutputDescriptor,
};
use lightning_signer::lightning;

use crate::byte_utils;
use crate::signer::keys::{
	DynSigner, InnerSign, KeysManager, PaymentSign, SignerFactory, SpendableKeysInterface,
};
use lightning::util::ser::Writeable;
use std::time::SystemTime;
use rand::{Rng, thread_rng};

pub struct InMemorySignerFactory {
	seed: [u8; 32],
	secp_ctx: Secp256k1<All>,
	node_secret: SecretKey,
}

impl PaymentSign for InMemorySigner {
	fn sign_counterparty_payment_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()> {
		self.sign_counterparty_payment_input(spend_tx, input_idx, descriptor, secp_ctx)
	}

	fn sign_dynamic_p2wsh_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()> {
		self.sign_dynamic_p2wsh_input(spend_tx, input_idx, descriptor, secp_ctx)
	}
}

impl InnerSign for InMemorySigner {
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

impl SignerFactory for InMemorySignerFactory {
	fn derive_channel_keys(
		&self, channel_master_key: &ExtendedPrivKey, channel_value_satoshis: u64, params: &[u8; 32],
	) -> DynSigner {
		let chan_id = byte_utils::slice_to_be64(&params[0..8]);
		assert!(chan_id <= std::u32::MAX as u64); // Otherwise the params field wasn't created by us
		let mut unique_start = Sha256::engine();
		unique_start.input(params);
		unique_start.input(&self.seed);

		// We only seriously intend to rely on the channel_master_key for true secure
		// entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
		// starting_time provided in the constructor) to be unique.
		let child_privkey = channel_master_key
			.ckd_priv(
				&self.secp_ctx,
				ChildNumber::from_hardened_idx(chan_id as u32).expect("key space exhausted"),
			)
			.expect("Your RNG is busted");
		unique_start.input(&child_privkey.private_key.key[..]);

		let seed = Sha256::from_engine(unique_start).into_inner();

		let commitment_seed = {
			let mut sha = Sha256::engine();
			sha.input(&seed);
			sha.input(&b"commitment seed"[..]);
			Sha256::from_engine(sha).into_inner()
		};
		macro_rules! key_step {
			($info: expr, $prev_key: expr) => {{
				let mut sha = Sha256::engine();
				sha.input(&seed);
				sha.input(&$prev_key[..]);
				sha.input(&$info[..]);
				SecretKey::from_slice(&Sha256::from_engine(sha).into_inner())
					.expect("SHA-256 is busted")
			}};
		}
		let funding_key = key_step!(b"funding key", commitment_seed);
		let revocation_base_key = key_step!(b"revocation base key", funding_key);
		let payment_key = key_step!(b"payment key", revocation_base_key);
		let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_key);
		let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);

		let signer = InMemorySigner::new(
			&self.secp_ctx,
			self.node_secret,
			funding_key,
			revocation_base_key,
			payment_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis,
			params.clone(),
		);

		DynSigner { inner: Box::new(signer) }
	}

	fn new(seed: &[u8; 32], node_secret: SecretKey) -> Self {
		InMemorySignerFactory { seed: seed.clone(), secp_ctx: Secp256k1::new(), node_secret }
	}
}

pub(crate) fn make_signer(
	_network: Network,
	ldk_data_dir: String,
) -> Box<dyn SpendableKeysInterface<Signer = DynSigner>> {
	// The key seed that we use to derive the node privkey (that corresponds to the node pubkey) and
	// other secret key material.
	let cur = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let keys_seed_path = format!("{}/keys_seed", ldk_data_dir.clone());
	let seed = if let Ok(seed) = fs::read(keys_seed_path.clone()) {
		assert_eq!(seed.len(), 32);
		let mut key = [0; 32];
		key.copy_from_slice(&seed);
		key
	} else {
		let mut key = [0; 32];
		thread_rng().fill_bytes(&mut key);
		let mut f = File::create(keys_seed_path).unwrap();
		f.write_all(&key).expect("Failed to write node keys seed to disk");
		f.sync_all().expect("Failed to sync node keys seed to disk");
		key
	};

	let manager: KeysManager<InMemorySignerFactory> = KeysManager::new(
		&seed,
		cur.as_secs(),
		cur.subsec_nanos()
	);
	Box::new(manager)
}
