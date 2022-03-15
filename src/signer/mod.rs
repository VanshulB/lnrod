use anyhow::Result;
use bitcoin::Network;

use keys::{DynSigner, SpendableKeysInterface};

pub mod keys;
mod vls;
mod test_signer;

pub const SIGNER_NAMES: [&str; 3] = ["test", "vls-local", "vls"];

pub async fn get_keys_manager(
	name: &str,
	vls_port: u16,
	network: Network,
	ldk_data_dir: String,
) -> Result<Box<dyn SpendableKeysInterface<Signer = DynSigner>>> {
	let manager: Box<dyn SpendableKeysInterface<Signer = DynSigner>> = match name {
		"test" => test_signer::make_signer(network, ldk_data_dir),
		"vls-local" => vls::make_signer(network, ldk_data_dir),
		"vls" => vls::make_remote_signer(vls_port, network, ldk_data_dir).await,
		_ => anyhow::bail!("not found"),
	};

	Ok(manager)
}
