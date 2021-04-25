use std::fs::read_to_string;
use std::path::Path;

use bitcoin::Network;
use clap::{App, Arg, ArgMatches};
use url::Url;

use lnrod::admin;
use lnrod::log_utils::{LOG_LEVEL_NAMES, parse_log_level};
use lnrod::node::NodeBuildArgs;
use lnrod::config::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let app = App::new("lnrod")
		.about("Lightning Rod Node")
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
			Arg::new("config")
				.short('f')
				.long("config")
				.about("config file, default DATADIR/config")
				.takes_value(true)
		)
		.arg(
			Arg::new("bitcoin")
				.about("Bitcoin RPC endpoint")
				.short('b')
				.long("bitcoin")
				.default_value("http://user:pass@localhost:18443")
				.takes_value(true)
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
		)
		.arg(
			Arg::new("dump-config")
				.long("dump-config")
		);
	let matches = app.clone().get_matches();

	let data_dir = matches.value_of_t_or_exit("datadir");
	let config_path = matches.value_of_t("config")
		.unwrap_or_else(|_| format!("{}/config", data_dir));
	let config = get_config(&matches, &config_path);

	if matches.is_present("dump-config") {
		println!("{}", toml::to_string(&config).unwrap());
		return Ok(())
	}

	let bitcoin_arg = matches.value_of_t_or_exit("bitcoin");
	let bitcoin_url = Url::parse(
		if matches.occurrences_of("bitcoin") > 0 { bitcoin_arg } else { config.bitcoin_rpc.clone().unwrap_or(bitcoin_arg) }
			.as_str()
	)?;
	// Network is regtest if specified on the command line or in the config file
	let network =
		if matches.occurrences_of("regtest") > 0 || config.regtest.unwrap_or(false)
		{ Network::Regtest } else { Network::Testnet };

	let console_log_level =
		parse_log_level(matches.value_of_t_or_exit("loglevelconsole"))
			.expect("loglevelconsole");
	let disk_log_level =
		parse_log_level(matches.value_of_t_or_exit("logleveldisk"))
			.expect("logleveldisk");

	let lnport_arg = matches.value_of_t_or_exit("lnport");
	let peer_listening_port =
		if matches.occurrences_of("lnport") > 0 { lnport_arg }
		else { config.lnport.unwrap_or(lnport_arg) };
	let rpcport_arg = matches.value_of_t_or_exit("rpcport");
	let rpc_port =
		if matches.occurrences_of("rpcport") > 0 { rpcport_arg }
		else { config.rpcport.unwrap_or(rpcport_arg) };

	let args = NodeBuildArgs {
		bitcoind_rpc_username: bitcoin_url.username().to_string(),
		bitcoind_rpc_password: bitcoin_url.password().expect("password").to_string(),
		bitcoind_rpc_host: bitcoin_url.host_str().expect("host").to_string(),
		bitcoind_rpc_port: bitcoin_url.port().expect("port"),
		storage_dir_path: data_dir,
		peer_listening_port,
		network,
		disk_log_level,
		console_log_level,
		config
	};

	admin::driver::start(rpc_port, args).expect("gRPC driver start");
	Ok(())
}

fn get_config(matches: &ArgMatches, config_path: &String) -> Config {
	let config_exists = Path::new(&config_path).exists();
	if matches.is_present("config") && !config_exists {
		panic!("missing config file");
	}
	let config: Config = if config_exists {
		let contents = read_to_string(config_path).unwrap();
		toml::from_str(contents.as_str()).unwrap()
	} else {
		Default::default()
	};
	config
}
