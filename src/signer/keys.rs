use std::any::Any;
use std::collections::HashSet;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, bail, Result};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as Sha256State;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::util::bip143;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{Network, Script, SigHashType, Transaction, TxIn, TxOut};
use lightning::chain::keysinterface::{
	BaseSign, DelayedPaymentOutputDescriptor, InMemorySigner, KeysInterface, Sign,
	SpendableOutputDescriptor, StaticPaymentOutputDescriptor,
};
use lightning::ln::chan_utils::{
	ChannelPublicKeys, ChannelTransactionParameters, CommitmentTransaction, HTLCOutputInCommitment,
	HolderCommitmentTransaction,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::ln::script::ShutdownScript;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning_signer::lightning;
use lightning_signer::util::transaction_utils;
use lightning_signer::util::transaction_utils::MAX_VALUE_MSAT;

use crate::byte_utils;
use crate::lightning::ln::chan_utils::ClosingTransaction;

/// Decouple creation of DynSigner from KeysManager
pub trait SignerFactory: Sync + Send {
	fn derive_channel_keys(
		&self, channel_master_key: &ExtendedPrivKey, channel_value_satoshis: u64, params: &[u8; 32],
	) -> DynSigner;
}

// TODO(devrandom) why is spend_spendable_outputs not in KeysInterface?
pub trait SpendableKeysInterface: KeysInterface + Send + Sync {
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction>;
}

pub(crate) struct DynKeysInterface {
	pub inner: Box<dyn SpendableKeysInterface<Signer = DynSigner>>,
}

impl DynKeysInterface {
	pub fn new(inner: Box<dyn SpendableKeysInterface<Signer = DynSigner>>) -> Self {
		DynKeysInterface { inner }
	}

	pub fn get_node_id(&self) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &self.get_node_secret())
	}
}

impl KeysInterface for DynKeysInterface {
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
		self.inner.get_channel_signer(inbound, channel_value_satoshis)
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.inner.get_secure_random_bytes()
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		self.inner.read_chan_signer(reader)
	}

	fn sign_invoice(&self, invoice_preimage: Vec<u8>) -> Result<RecoverableSignature, ()> {
		self.inner.sign_invoice(invoice_preimage)
	}
}

impl SpendableKeysInterface for DynKeysInterface {
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: Script, feerate_sat_per_1000_weight: u32,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction> {
		self.inner.spend_spendable_outputs(
			descriptors,
			outputs,
			change_destination_script,
			feerate_sat_per_1000_weight,
			secp_ctx,
		)
	}
}

// Copied from keysinterface.rs and decoupled from InMemorySigner

/// Simple KeysInterface implementor that takes a 32-byte seed for use as a BIP 32 extended key
/// and derives keys from that.
///
/// Your node_id is seed/0'
/// ChannelMonitor closes may use seed/1'
/// Cooperative closes may use seed/2'
/// The two close keys may be needed to claim on-chain funds!
pub struct KeysManager<F: SignerFactory> {
	secp_ctx: Secp256k1<secp256k1::All>,
	node_secret: SecretKey,
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
	factory: F,
}

impl<F: SignerFactory> KeysManager<F> {
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
		seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32, factory: F,
	) -> Self {
		let secp_ctx = Secp256k1::new();
		// Note that when we aren't serializing the key, network doesn't matter
		match ExtendedPrivKey::new_master(Network::Testnet, seed) {
			Ok(master_key) => {
				let node_secret = master_key
					.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(0).unwrap())
					.expect("Your RNG is busted")
					.private_key
					.key;
				let destination_script = match master_key
					.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1).unwrap())
				{
					Ok(destination_key) => {
						let wpubkey_hash = WPubkeyHash::hash(
							&ExtendedPubKey::from_private(&secp_ctx, &destination_key)
								.public_key
								.to_bytes(),
						);
						Builder::new()
							.push_opcode(opcodes::all::OP_PUSHBYTES_0)
							.push_slice(&wpubkey_hash.into_inner())
							.into_script()
					}
					Err(_) => panic!("Your RNG is busted"),
				};
				let shutdown_pubkey = match master_key
					.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap())
				{
					Ok(shutdown_key) => {
						ExtendedPubKey::from_private(&secp_ctx, &shutdown_key).public_key.key
					}
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

				let mut res = KeysManager {
					secp_ctx,
					node_secret,

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
				};
				let secp_seed = res.get_secure_random_bytes();
				res.secp_ctx.seeded_randomize(&secp_seed);
				res
			}
			Err(_) => panic!("Your rng is busted"),
		}
	}
	/// Derive an old Sign containing per-channel secrets based on a key derivation parameters.
	///
	/// Key derivation parameters are accessible through a per-channel secrets
	/// Sign::channel_keys_id and is provided inside DynamicOuputP2WSH in case of
	/// onchain output detection for which a corresponding delayed_payment_key must be derived.
	pub fn derive_channel_keys(&self, channel_value_satoshis: u64, params: &[u8; 32]) -> DynSigner {
		self.factory.derive_channel_keys(&self.channel_master_key, channel_value_satoshis, params)
	}
}

impl<F: SignerFactory> KeysInterface for KeysManager<F> {
	type Signer = DynSigner;

	fn get_node_secret(&self) -> SecretKey {
		self.node_secret.clone()
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
		self.derive_channel_keys(channel_value_satoshis, &id)
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
		sha.input(&child_privkey.private_key.key[..]);

		sha.input(b"Unique Secure Random Bytes Salt");
		Sha256::from_engine(sha).into_inner()
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		let mut cursor = std::io::Cursor::new(reader);
		// TODO(devrandom) make this polymorphic
		let signer = InMemorySigner::read(&mut cursor)?;
		Ok(DynSigner { inner: Box::new(signer) })
	}

	fn sign_invoice(&self, invoice_preimage: Vec<u8>) -> Result<RecoverableSignature, ()> {
		let hash = Sha256::hash(invoice_preimage.as_slice());
		let message = secp256k1::Message::from_slice(&hash).unwrap();
		Ok(self.secp_ctx.sign_recoverable(&message, &self.get_node_secret()))
	}
}

impl<F: SignerFactory> SpendableKeysInterface for KeysManager<F> {
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
						bail!("Descriptor was duplicated");
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
						bail!("Descriptor was duplicated");
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
						bail!("Descriptor was duplicated");
					}
				}
			}
			if input_value > MAX_VALUE_MSAT / 1000 {
				bail!("Input value greater than max satoshis");
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
		.map_err(|_| anyhow!("failed to add change output"))?;

		let mut keys_cache: Option<(DynSigner, [u8; 32])> = None;
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
					spend_tx.input[input_idx].witness = keys_cache
						.as_ref()
						.unwrap()
						.0
						.sign_counterparty_payment_input_t(
							&spend_tx,
							input_idx,
							&descriptor,
							&secp_ctx,
						)
						.unwrap();
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
					spend_tx.input[input_idx].witness = keys_cache
						.as_ref()
						.unwrap()
						.0
						.sign_dynamic_p2wsh_input_t(&spend_tx, input_idx, &descriptor, &secp_ctx)
						.unwrap();
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
					let pubkey = ExtendedPubKey::from_private(&secp_ctx, &secret).public_key;
					if derivation_idx == 2 {
						assert_eq!(pubkey.key, self.shutdown_pubkey);
					}
					let witness_script =
						bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
					let sighash = ::bitcoin::secp256k1::Message::from_slice(
						&bip143::SigHashCache::new(&spend_tx).signature_hash(
							input_idx,
							&witness_script,
							output.value,
							SigHashType::All,
						)[..],
					)
					.unwrap();
					let sig = secp_ctx.sign(&sighash, &secret.private_key.key);
					spend_tx.input[input_idx].witness.push(sig.serialize_der().to_vec());
					spend_tx.input[input_idx].witness[0].push(SigHashType::All as u8);
					spend_tx.input[input_idx].witness.push(pubkey.key.serialize().to_vec());
				}
			}
			input_idx += 1;
		}
		Ok(spend_tx)
	}
}

// XXX why are these two calls not in `Sign`?
pub trait PaymentSign: BaseSign {
	fn sign_counterparty_payment_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()>;
	fn sign_dynamic_p2wsh_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()>;
}

/// Helper to allow DynSigner to clone itself
pub trait InnerSign: PaymentSign + Send + Sync {
	fn box_clone(&self) -> Box<dyn InnerSign>;
	fn as_any(&self) -> &dyn Any;
	fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), ::std::io::Error>;
}

pub struct DynSigner {
	pub inner: Box<dyn InnerSign>,
}

impl Sign for DynSigner {}

impl Clone for DynSigner {
	fn clone(&self) -> Self {
		DynSigner { inner: self.inner.box_clone() }
	}
}

impl PaymentSign for DynSigner {
	fn sign_counterparty_payment_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()> {
		self.inner.sign_counterparty_payment_input_t(spend_tx, input_idx, descriptor, secp_ctx)
	}

	fn sign_dynamic_p2wsh_input_t(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<All>,
	) -> Result<Vec<Vec<u8>>, ()> {
		self.inner.sign_dynamic_p2wsh_input_t(spend_tx, input_idx, descriptor, secp_ctx)
	}
}

// This is taken care of by KeysInterface
impl Readable for DynSigner {
	fn read<R: Read>(_reader: &mut R) -> Result<Self, DecodeError> {
		unimplemented!()
	}
}

impl BaseSign for DynSigner {
	fn get_per_commitment_point(
		&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> PublicKey {
		self.inner.get_per_commitment_point(idx, secp_ctx)
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		self.inner.release_commitment_secret(idx)
	}

	fn validate_holder_commitment(&self, holder_tx: &HolderCommitmentTransaction) -> Result<(), ()> {
		self.inner.validate_holder_commitment(holder_tx)
	}

	fn pubkeys(&self) -> &ChannelPublicKeys {
		self.inner.pubkeys()
	}

	fn channel_keys_id(&self) -> [u8; 32] {
		self.inner.channel_keys_id()
	}

	fn sign_counterparty_commitment(
		&self, commitment_tx: &CommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(Signature, Vec<Signature>), ()> {
		self.inner.sign_counterparty_commitment(commitment_tx, secp_ctx)
	}

	fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
		self.inner.validate_counterparty_revocation(idx, secret)
	}

	fn sign_holder_commitment_and_htlcs(
		&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(Signature, Vec<Signature>), ()> {
		self.inner.sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx)
	}

	fn unsafe_sign_holder_commitment_and_htlcs(
		&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<All>,
	) -> Result<(Signature, Vec<Signature>), ()> {
		self.inner.unsafe_sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx)
	}

	fn sign_justice_revoked_output(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Signature, ()> {
		self.inner.sign_justice_revoked_output(
			justice_tx,
			input,
			amount,
			per_commitment_key,
			secp_ctx,
		)
	}

	fn sign_justice_revoked_htlc(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> Result<Signature, ()> {
		self.inner.sign_justice_revoked_htlc(
			justice_tx,
			input,
			amount,
			per_commitment_key,
			htlc,
			secp_ctx,
		)
	}

	fn sign_counterparty_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.sign_counterparty_htlc_transaction(
			htlc_tx,
			input,
			amount,
			per_commitment_point,
			htlc,
			secp_ctx,
		)
	}

	fn sign_closing_transaction(
		&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.sign_closing_transaction(closing_tx, secp_ctx)
	}

	fn sign_channel_announcement(
		&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement(msg, secp_ctx)
	}

	fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
		self.inner.ready_channel(channel_parameters)
	}
}

impl Writeable for DynSigner {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		let inner = self.inner.as_ref();
		let mut buf = Vec::new();
		inner.vwrite(&mut buf)?;
		writer.write_all(&buf)
	}
}

#[cfg(test)]
mod tests {
}
