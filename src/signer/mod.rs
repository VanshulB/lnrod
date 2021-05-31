use std::time::SystemTime;

use anyhow::Result;

use keys::{DynSigner, SpendableKeysInterface};

pub mod keys;
mod rust_lightning_signer;
mod test_signer;

pub const SIGNER_NAMES: [&str; 2] = ["test", "rls"];

pub fn get_keys_manager(
	name: &str, seed: &[u8; 32],
) -> Result<Box<dyn SpendableKeysInterface<Signer = DynSigner>>> {
	let cur = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let manager: Box<dyn SpendableKeysInterface<Signer = DynSigner>> = match name {
		"test" => test_signer::make_signer(&seed, cur),
		"rls" => rust_lightning_signer::make_signer(),
		_ => anyhow::bail!("not found"),
	};

	Ok(manager)
}
