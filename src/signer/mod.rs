use anyhow::Result;
use bitcoin::Network;

use keys::{DynSigner, SpendableKeysInterface};

pub mod keys;
mod rust_lightning_signer;
mod test_signer;

pub const SIGNER_NAMES: [&str; 2] = ["test", "rls"];

pub fn get_keys_manager(
	name: &str,
	network: Network,
	ldk_data_dir: String,
) -> Result<Box<dyn SpendableKeysInterface<Signer = DynSigner>>> {
	let manager: Box<dyn SpendableKeysInterface<Signer = DynSigner>> = match name {
		"test" => test_signer::make_signer(network, ldk_data_dir),
		"rls" => rust_lightning_signer::make_signer(network, ldk_data_dir),
		_ => anyhow::bail!("not found"),
	};

	Ok(manager)
}
