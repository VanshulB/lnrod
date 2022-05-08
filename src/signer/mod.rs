use anyhow::Result;
use bitcoin::Network;
use tokio::runtime::Handle;

use crate::util::Shutter;
use crate::{BitcoindClient, DynSigner, SpendableKeysInterface};

pub mod keys;
mod test_signer;
mod vls;
mod vls2;

pub const SIGNER_NAMES: [&str; 5] = ["test", "vls-local", "vls", "vls2-null", "vls2-grpc"];

/// Get the keys manager and the sweep address
pub async fn get_keys_manager(
	shutter: Shutter, signer_handle: Handle, name: &str, vls_port: u16, network: Network,
	ldk_data_dir: String, bitcoind_client: BitcoindClient,
) -> Result<Box<dyn SpendableKeysInterface<Signer = DynSigner>>> {
	let sweep_address = bitcoind_client.get_new_address("".to_string()).await;

	let manager: Box<dyn SpendableKeysInterface<Signer = DynSigner>> = match name {
		"test" => test_signer::make_signer(network, ldk_data_dir, sweep_address),
		"vls-local" => vls::make_signer(network, ldk_data_dir, sweep_address),
		"vls" => vls::make_remote_signer(vls_port, network, ldk_data_dir, sweep_address).await,
		"vls2-null" => vls2::make_null_signer(network, ldk_data_dir, sweep_address).await,
		"vls2-grpc" => {
			vls2::make_grpc_signer(
				shutter,
				signer_handle,
				vls_port,
				network,
				ldk_data_dir,
				sweep_address,
			)
			.await
		}
		_ => anyhow::bail!("not found"),
	};

	let label = format!("sweep-{}", manager.get_node_id().to_string());
	bitcoind_client.set_label(manager.get_sweep_address(), label).await;
	Ok(manager)
}
