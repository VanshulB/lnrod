use std::cell::RefCell;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Result};
use log::{debug, info};
use regex::Regex;
use tokio::net::TcpStream;
use tokio_socks::IntoTargetAddr;
use tokio_socks::tcp::Socks5Stream;
use torut::control::{AsyncEvent, AuthenticatedConn, ConnError, UnauthenticatedConn};
use torut::onion::{OnionAddressV3, TorSecretKeyV3};
use torut::utils::AutoKillChild;

mod echo;
pub mod server;

type ConnectionHandler = Box<dyn Fn(AsyncEvent<'static>)  -> Pin<Box<dyn Future<Output = Result<(), ConnError>>>>>;
type AuthenticatedControlConnection = AuthenticatedConn<TcpStream, ConnectionHandler>;

pub struct TorConnector {
	tor_proxy_addr: SocketAddr,
}

pub struct TorManager {
	data_dir_prefix: PathBuf,
	// kills the child when dropped
	#[allow(unused)]
	child: AutoKillChild,
	control_connection: RefCell<AuthenticatedControlConnection>,
	tor_proxy_addr: SocketAddr,
}

impl TorManager {
	pub async fn start(data_dir_prefix: &Path) -> Self {
		let data_dir = data_dir_prefix.join("tor");

		// ignore error if doesn't exist
		let _ = fs::remove_dir_all(&data_dir);
		fs::create_dir(&data_dir).expect("create_dir");

		let control_port_path = data_dir.join("control_port");
		let child = run_tor(&data_dir, Path::new("/usr/bin/tor"), &mut [
			"--CookieAuthentication", "1",
			"--SocksPort", "auto",
			"--ControlPort", "auto",
			"--ControlPortWriteToFile", control_port_path.to_str().unwrap(),
			"--DataDirectory", data_dir.to_str().unwrap(),
		]).expect("Starting tor filed");
		let child = AutoKillChild::new(child);

		// Wait for control port file to appear
		for _ in 0..10 {
			if fs::read_to_string(&control_port_path).is_ok() {
				break;
			}
			sleep(Duration::from_secs(1));
		}

		let control_port = get_control_port(&control_port_path);
		let tor_control_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, control_port));

		info!("Tor instance started, control at {}", control_port);

		// Get an authenticated connection to the Tor via the Tor Controller protocol.
		let mut control_connection =
			connect_control(tor_control_addr).await.expect("connect to control port");

		let socks_addr_string = control_connection.get_info("net/listeners/socks").await.expect("socks port");
		let tor_proxy_addr = decode_socks_port(socks_addr_string);
		info!("socks port {}", tor_proxy_addr);
		TorManager {
			data_dir_prefix: data_dir_prefix.to_path_buf(),
			child,
			control_connection: RefCell::new(control_connection),
			tor_proxy_addr,
		}
	}

	// Expose an onion service that re-directs to the given port.
	pub async fn init_service(&self, port: u16) -> OnionAddressV3 {
		let key = get_or_generate_onion_secret(&self.data_dir_prefix);
		self.control_connection.borrow_mut()
			.add_onion_v3(&key, false, false, false, None, &mut [
				(port, SocketAddr::new(IpAddr::from(Ipv4Addr::new(127,0,0,1)), port)),
			].iter()).await.unwrap();

		let address = key.public().get_onion_address();
		info!("onion service address {}", address);
		address
	}

	pub fn get_connector(&self) -> TorConnector {
		TorConnector {
			tor_proxy_addr: self.tor_proxy_addr
		}
	}
}

impl TorConnector {
	pub async fn connect_proxy(&self, addr: String) -> Result<TcpStream> {
		connect_tor_socks_proxy(self.tor_proxy_addr, addr).await
	}
}

async fn connect_control(tor_control_addr: SocketAddr) -> Result<AuthenticatedControlConnection> {
	debug!("before connect to control port");

	let stream = connect_tor_cp(tor_control_addr).await?;

	debug!("connected to control port");

	let mut utc = UnauthenticatedConn::new(stream);

	let info = match utc.load_protocol_info().await {
		Ok(info) => info,
		Err(_) => bail!("failed to load protocol info from Tor")
	};
	let ad = info.make_auth_data()?.expect("failed to make auth data");

	if utc.authenticate(&ad).await.is_err() {
		bail!("failed to authenticate with Tor")
	}
	let mut ac = utc.into_authenticated().await;

	ac.set_async_event_handler(None);

	ac.take_ownership().await.unwrap();
	Ok(ac)
}

fn decode_socks_port(socks_addr_string: String) -> SocketAddr {
	let socks_port_pattern = Regex::new("^\"127.0.0.1:(\\d+)\"$").expect("regex");
	let socks_port_str = socks_port_pattern
		.captures(&socks_addr_string).expect("parse")
		.get(1).expect("capture").as_str();
	let socks_port = socks_port_str.parse().expect("integer port");
	let tor_proxy_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port));
	tor_proxy_addr
}

fn get_control_port(control_port_path: &Path) -> u16 {
	let control_addr_string = fs::read_to_string(&control_port_path).expect("control port path");
	let control_pattern = Regex::new(r"^PORT=127.0.0.1:(\d+)").expect("regex");
	let control_port_str = control_pattern
		.captures(&control_addr_string).expect("parse")
		.get(1).expect("capture").as_str();
	let control_port = control_port_str.parse().expect("integer port");
	control_port
}

fn get_or_generate_onion_secret(data_dir_prefix: &Path) -> TorSecretKeyV3 {
	let key_path = data_dir_prefix.join("onion.key");
	if let Ok(key_str) = fs::read_to_string(&key_path) {
		let data: [u8; 64] = hex::decode(key_str).expect("hex").as_slice().try_into().unwrap();
		TorSecretKeyV3::from(data)
	} else {
		let key = TorSecretKeyV3::generate();
		let encoded = hex::encode(key.as_bytes());
		fs::write(&key_path, encoded).expect("write");
		key
	}
}

fn run_tor(data_dir: &Path, path: &Path, args: &[&str]) -> Result<Child, std::io::Error>
{
	let stdout_file = File::create(data_dir.join("out.log")).expect("stdout");
	let stderr_file = File::create(data_dir.join("err.log")).expect("stderr");
	let c = Command::new(path)
		.args(args)
		// .env_clear()
		.stdout(Stdio::from(stdout_file))
		.stderr(Stdio::from(stderr_file))
		.stdin(Stdio::null())
		.spawn()?;
	Ok(c)
}

async fn connect_tor_cp(addr: SocketAddr) -> Result<TcpStream> {
	let sock = TcpStream::connect(addr).await?;
	Ok(sock)
}

async fn connect_tor_socks_proxy<'a>(proxy: SocketAddr, dest: impl IntoTargetAddr<'a>) -> Result<TcpStream> {
	let sock = Socks5Stream::connect(proxy, dest).await?;
	Ok(sock.into_inner())
}
