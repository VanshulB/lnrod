use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use anyhow::Result;
use log::{info, LevelFilter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::echo;
use super::TorManager;
use crate::log_utils::ConsoleLogger;

const PORT: u16 = 8007;
static CONSOLE_LOGGER: ConsoleLogger = ConsoleLogger;

#[tokio::main]
pub async fn test_onion_server() -> Result<()> {
	log::set_logger(&CONSOLE_LOGGER)?;
	log::set_max_level(LevelFilter::Debug);

	let echo_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT));

	let data_dir_prefix = Path::new("/tmp/x");

	//
	// Start an echo server
	//
	tokio::spawn(async move { echo::run(echo_addr).await.expect("failed to start echo server") });

	let manager = TorManager::start(data_dir_prefix).await;
	let onion_address = manager.init_service(PORT).await;
	let onion_address_with_port = format!("{}:{}", onion_address, PORT);

	// Connect to the echo server via the Tor network.
	let mut stream = manager.get_connector().connect_proxy(onion_address_with_port).await?;
	info!("TorStream connection established");

	info!("writing 'ping' to the stream");
	stream.write_all(b"ping\n").await?;

	info!("reading from the stream ...");
	let mut buf = [0u8; 128];
	let n = stream.read(&mut buf).await?;
	info!("received {} bytes: {}", n, std::str::from_utf8(&buf[0..n]).unwrap());

	Ok(())
}
