use bitcoin::Network;
use clap::{App, Arg};
use url::Url;

use lnrod::admin;
use lnrod::log_utils::{parse_log_level, LOG_LEVEL_NAMES};
use lnrod::node::NodeBuildArgs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let app = App::new("lnrod")
		.about("LDK node")
		.arg(
			Arg::new("lnport")
				.about("Lightning peer listen port")
				.short('l')
				.long("lnport")
				.default_value("9901")
				.validator(|s| s.parse::<u16>())
				.takes_value(true),
		)
		.arg(
			Arg::new("rpcport")
				.about("Lightning peer listen port")
				.short('p')
				.long("rpcport")
				.default_value("8801")
				.validator(|s| s.parse::<u16>())
				.takes_value(true),
		)
		.arg(
			Arg::new("datadir")
				.short('d')
				.long("datadir")
				.default_value("data")
				.about("data directory")
				.takes_value(true),
		)
		.arg(
			Arg::new("bitcoin")
				.about("Bitcoin RPC endpoint")
				.short('b')
				.long("bitcoin")
				.default_value("http://user:pass@localhost:18443")
				.takes_value(true),
		)
		.arg(Arg::new("regtest").long("regtest"))
		.arg(
			Arg::new("logleveldisk")
				.about("logging level to disk")
				.short('v')
				.long("log-level-disk")
				.possible_values(&LOG_LEVEL_NAMES)
				.default_value("TRACE")
				.takes_value(true),
		)
		.arg(
			Arg::new("loglevelconsole")
				.about("logging level to console")
				.short('V')
				.long("log-level-console")
				.possible_values(&LOG_LEVEL_NAMES)
				.default_value("INFO")
				.takes_value(true),
		);
	let matches = app.clone().get_matches();
	let bitcoin_url = Url::parse(matches.value_of("bitcoin").unwrap())?;

	let network = if matches.is_present("regtest") { Network::Regtest } else { Network::Testnet };
	let datadir = matches.value_of("datadir").unwrap().to_string();
	let args = NodeBuildArgs {
		bitcoind_rpc_username: bitcoin_url.username().to_string(),
		bitcoind_rpc_password: bitcoin_url.password().expect("password").to_string(),
		bitcoind_rpc_host: bitcoin_url.host_str().expect("host").to_string(),
		bitcoind_rpc_port: bitcoin_url.port().expect("port"),
		storage_dir_path: datadir.clone(),
		peer_listening_port: matches.value_of("lnport").unwrap().parse().unwrap(),
		network,
		disk_log_level: parse_log_level(matches.value_of("logleveldisk").unwrap().to_string())
			.expect("logleveldisk"),
		console_log_level: parse_log_level(
			matches.value_of("loglevelconsole").unwrap().to_string(),
		)
		.expect("loglevelconsole"),
	};

	let rpc_port = matches.value_of("rpcport").unwrap();

	admin::driver::start(rpc_port.parse().expect("port number"), args).expect("gRPC driver start");
	Ok(())
}

#[test]
fn test_url() {
	let url = Url::parse("http://user:pass@localhost:1234");
	println!("{:?}", url)
}
