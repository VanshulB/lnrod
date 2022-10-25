use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, bail, Result};
use bitcoin::bech32::u5;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as Sha256State;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::secp256k1::{ecdh::SharedSecret, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::util::sighash;
use bitcoin::{secp256k1, Address, Witness};
use bitcoin::{
	EcdsaSighashType, Network, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut,
};
use lightning::chain::keysinterface::{
	DelayedPaymentOutputDescriptor, InMemorySigner, KeysInterface, Recipient,
	SpendableOutputDescriptor, StaticPaymentOutputDescriptor,
};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use lightning::util::invoice::construct_invoice_preimage;
use lightning::util::ser::ReadableArgs;
use lightning_signer::util::transaction_utils;
use lightning_signer::util::transaction_utils::MAX_VALUE_MSAT;
use lightning_signer::{bitcoin, lightning};

use crate::chain::keysinterface::KeyMaterial;
use crate::signer::test_signer::InMemorySignerFactory;
use crate::{byte_utils, DynSigner, SpendableKeysInterface};

// Copied from keysinterface.rs and decoupled from InMemorySigner

/// Simple KeysInterface implementor that takes a 32-byte seed for use as a BIP 32 extended key
/// and derives keys from that.
///
/// Your node_id is seed/0'
/// ChannelMonitor closes may use seed/1'
/// Cooperative closes may use seed/2'
/// The two close keys may be needed to claim on-chain funds!
pub struct KeysManager {
	secp_ctx: Secp256k1<secp256k1::All>,
	node_secret: SecretKey,
	inbound_payment_key: KeyMaterial,
	destination_script: Script,
	shutdown_pubkey: PublicKey,
	channel_master_key: ExtendedPrivKey,
	channel_child_index: AtomicUsize,

	rand_bytes_master_key: ExtendedPrivKey,
	rand_bytes_child_index: AtomicUsize,
	rand_bytes_unique_start: Sha256State,

	seed: [u8; 32],
	starting_time_secs: u64,
	starting_time_nanos: u32,
	sweep_address: Address,
	pub factory: InMemorySignerFactory,
}

impl KeysManager {
	/// Constructs a KeysManager from a 32-byte seed. If the seed is in some way biased (eg your
	/// CSRNG is busted) this may panic (but more importantly, you will possibly lose funds).
	/// starting_time isn't strictly required to actually be a time, but it must absolutely,
	/// without a doubt, be unique to this instance. ie if you start multiple times with the same
	/// seed, starting_time must be unique to each run. Thus, the easiest way to achieve this is to
	/// simply use the current time (with very high precision).
	///
	/// The seed MUST be backed up safely prior to use so that the keys can be re-created, however,
	/// obviously, starting_time should be unique every time you reload the library - it is only
	/// used to generate new ephemeral key data (which will be stored by the individual channel if
	/// necessary).
	///
	/// Note that the seed is required to recover certain on-chain funds independent of
	/// ChannelMonitor data, though a current copy of ChannelMonitor data is also required for any
	/// channel, and some on-chain during-closing funds.
	///
	/// Note that until the 0.1 release there is no guarantee of backward compatibility between
	/// versions. Once the library is more fully supported, the docs will be updated to include a
	/// detailed description of the guarantee.
	pub fn new(
		seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32, sweep_address: Address,
	) -> Self {
		let secp_ctx = Secp256k1::new();
		// Note that when we aren't serializing the key, network doesn't matter
		let master_key =
			ExtendedPrivKey::new_master(Network::Testnet, seed).expect("your RNG is busted");
		let node_secret = master_key
			.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(0).unwrap())
			.expect("Your RNG is busted")
			.private_key;
		let destination_script = match master_key
			.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1).unwrap())
		{
			Ok(destination_key) => {
				let wpubkey_hash = WPubkeyHash::hash(
					&ExtendedPubKey::from_priv(&secp_ctx, &destination_key).public_key.serialize(),
				);
				Builder::new()
					.push_opcode(opcodes::all::OP_PUSHBYTES_0)
					.push_slice(&wpubkey_hash.into_inner())
					.into_script()
			}
			Err(_) => panic!("Your RNG is busted"),
		};
		let shutdown_pubkey =
			match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap()) {
				Ok(shutdown_key) => ExtendedPubKey::from_priv(&secp_ctx, &shutdown_key).public_key,
				Err(_) => panic!("Your RNG is busted"),
			};
		let channel_master_key = master_key
			.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3).unwrap())
			.expect("Your RNG is busted");
		let rand_bytes_master_key = master_key
			.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(4).unwrap())
			.expect("Your RNG is busted");

		let mut rand_bytes_unique_start = Sha256::engine();
		rand_bytes_unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
		rand_bytes_unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
		rand_bytes_unique_start.input(seed);

		let inbound_payment_key: SecretKey = master_key
			.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(5).unwrap())
			.expect("Your RNG is busted")
			.private_key;
		let mut inbound_pmt_key_bytes = [0; 32];
		inbound_pmt_key_bytes.copy_from_slice(inbound_payment_key.as_ref());

		let factory = InMemorySignerFactory::new(&seed, node_secret);

		let mut res = KeysManager {
			secp_ctx,
			node_secret,

			inbound_payment_key: KeyMaterial(inbound_pmt_key_bytes),
			destination_script,
			shutdown_pubkey,

			channel_master_key,
			channel_child_index: AtomicUsize::new(0),

			rand_bytes_master_key,
			rand_bytes_child_index: AtomicUsize::new(0),
			rand_bytes_unique_start,

			seed: *seed,
			starting_time_secs,
			starting_time_nanos,
			factory,
			sweep_address,
		};
		let secp_seed = res.get_secure_random_bytes();
		res.secp_ctx.seeded_randomize(&secp_seed);
		res
	}
	/// Derive an old Sign containing per-channel secrets based on a key derivation parameters.
	///
	/// Key derivation parameters are accessible through a per-channel secrets
	/// Sign::channel_keys_id and is provided inside DynamicOuputP2WSH in case of
	/// onchain output detection for which a corresponding delayed_payment_key must be derived.
	pub fn derive_channel_keys(
		&self, channel_value_satoshis: u64, params: &[u8; 32],
	) -> InMemorySigner {
		self.factory.derive_channel_keys(&self.channel_master_key, channel_value_satoshis, params)
	}
}

impl KeysInterface for KeysManager {
	type Signer = DynSigner;

	fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
		match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = self.get_node_secret(recipient)?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_destination_script(&self) -> Script {
		self.destination_script.clone()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		ShutdownScript::new_p2wpkh(&WPubkeyHash::hash(&self.shutdown_pubkey.serialize()))
	}

	fn get_channel_signer(&self, _inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
		let child_ix = self.channel_child_index.fetch_add(1, Ordering::AcqRel);
		assert!(child_ix <= std::u32::MAX as usize);
		let mut id = [0; 32];
		id[0..8].copy_from_slice(&byte_utils::be64_to_array(child_ix as u64));
		id[8..16].copy_from_slice(&byte_utils::be64_to_array(self.starting_time_nanos as u64));
		id[16..24].copy_from_slice(&byte_utils::be64_to_array(self.starting_time_secs));
		DynSigner::new(self.derive_channel_keys(channel_value_satoshis, &id))
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut sha = self.rand_bytes_unique_start.clone();

		let child_ix = self.rand_bytes_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self
			.rand_bytes_master_key
			.ckd_priv(
				&self.secp_ctx,
				ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted"),
			)
			.expect("Your RNG is busted");
		sha.input(child_privkey.private_key.as_ref());

		sha.input(b"Unique Secure Random Bytes Salt");
		Sha256::from_engine(sha).into_inner()
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		let mut cursor = std::io::Cursor::new(reader);
		// TODO(devrandom) make this polymorphic
		let signer = InMemorySigner::read(&mut cursor, self.node_secret)?;
		Ok(DynSigner { inner: Box::new(signer) })
	}

	fn sign_invoice(
		&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		let invoice_preimage = construct_invoice_preimage(&hrp_bytes, &invoice_data);
		let hash = Sha256::hash(invoice_preimage.as_slice());
		let message = secp256k1::Message::from_slice(&hash).unwrap();
		Ok(self
			.secp_ctx
			.sign_ecdsa_recoverable(&message, &self.get_node_secret(recipient).unwrap()))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inbound_payment_key
	}
}

impl SpendableKeysInterface for KeysManager {
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
		secp_ctx: &Secp256k1<secp256k1::All>,
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
						sequence: Sequence::ZERO,
						witness: Witness::default(),
					});
					witness_weight += StaticPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					input_value += descriptor.output.value;
					if !output_set.insert(descriptor.outpoint) {
						bail!("Descriptor was duplicated");
					}
				}
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					input.push(TxIn {
						previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: Sequence(descriptor.to_self_delay as u32),
						witness: Witness::default(),
					});
					witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					input_value += descriptor.output.value;
					if !output_set.insert(descriptor.outpoint) {
						bail!("Descriptor was duplicated");
					}
				}
				SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
					input.push(TxIn {
						previous_output: outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: Sequence::ZERO,
						witness: Witness::default(),
					});
					witness_weight += 1 + 73 + 34;
					input_value += output.value;
					if !output_set.insert(*outpoint) {
						bail!("Descriptor was duplicated");
					}
				}
			}
			if input_value > MAX_VALUE_MSAT / 1000 {
				bail!("Input value greater than max satoshis");
			}
		}
		let mut spend_tx =
			Transaction { version: 2, lock_time: PackedLockTime(0), input, output: outputs };
		transaction_utils::maybe_add_change_output(
			&mut spend_tx,
			input_value,
			witness_weight,
			feerate_sat_per_1000_weight,
			change_destination_script,
		)
		.map_err(|_| anyhow!("failed to add change output"))?;

		let mut keys_cache: Option<(InMemorySigner, [u8; 32])> = None;
		let mut input_idx = 0;
		for outp in descriptors {
			match outp {
				SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
					if keys_cache.is_none()
						|| keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id
					{
						keys_cache = Some((
							self.derive_channel_keys(
								descriptor.channel_value_satoshis,
								&descriptor.channel_keys_id,
							),
							descriptor.channel_keys_id,
						));
					}
					spend_tx.input[input_idx].witness = Witness::from_vec(
						keys_cache
							.as_ref()
							.unwrap()
							.0
							.sign_counterparty_payment_input(
								&spend_tx,
								input_idx,
								&descriptor,
								&secp_ctx,
							)
							.unwrap(),
					);
				}
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					if keys_cache.is_none()
						|| keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id
					{
						keys_cache = Some((
							self.derive_channel_keys(
								descriptor.channel_value_satoshis,
								&descriptor.channel_keys_id,
							),
							descriptor.channel_keys_id,
						));
					}
					spend_tx.input[input_idx].witness = Witness::from_vec(
						keys_cache
							.as_ref()
							.unwrap()
							.0
							.sign_dynamic_p2wsh_input(&spend_tx, input_idx, &descriptor, &secp_ctx)
							.unwrap(),
					);
				}
				SpendableOutputDescriptor::StaticOutput { ref output, .. } => {
					let derivation_idx =
						if output.script_pubkey == self.destination_script { 1 } else { 2 };
					let secret = {
						// Note that when we aren't serializing the key, network doesn't matter
						match ExtendedPrivKey::new_master(Network::Testnet, &self.seed) {
							Ok(master_key) => {
								match master_key.ckd_priv(
									&secp_ctx,
									ChildNumber::from_hardened_idx(derivation_idx)
										.expect("key space exhausted"),
								) {
									Ok(key) => key,
									Err(_) => panic!("Your RNG is busted"),
								}
							}
							Err(_) => panic!("Your rng is busted"),
						}
					};
					let pubkey = bitcoin::PublicKey::new(
						ExtendedPubKey::from_priv(&secp_ctx, &secret).public_key,
					);
					if derivation_idx == 2 {
						assert_eq!(pubkey.inner, self.shutdown_pubkey);
					}
					let witness_script = Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
					let sighash = secp256k1::Message::from_slice(
						&sighash::SighashCache::new(&spend_tx)
							.segwit_signature_hash(
								input_idx,
								&witness_script,
								output.value,
								EcdsaSighashType::All,
							)
							.unwrap()
							.as_ref(),
					)
					.unwrap();
					let sig = secp_ctx.sign_ecdsa(&sighash, &secret.private_key);
					let mut sig_ser = sig.serialize_der().to_vec();
					sig_ser.push(EcdsaSighashType::All as u8);
					spend_tx.input[input_idx].witness.push(sig_ser);
					spend_tx.input[input_idx].witness.push(pubkey.inner.serialize().to_vec());
				}
			}
			input_idx += 1;
		}
		Ok(spend_tx)
	}

	fn get_sweep_address(&self) -> Address {
		self.sweep_address.clone()
	}

	fn get_node_id(&self) -> PublicKey {
		PublicKey::from_secret_key(
			&Secp256k1::new(),
			&self.get_node_secret(Recipient::Node).unwrap(),
		)
	}

	fn sign_from_wallet(
		&self, _psbt: &PartiallySignedTransaction, _derivations: Vec<u32>,
	) -> PartiallySignedTransaction {
		unimplemented!("TODO")
	}
}

#[cfg(test)]
mod tests {}
