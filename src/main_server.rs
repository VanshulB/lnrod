use std::fs::read_to_string;
use std::path::Path;

use anyhow::Result;
use bitcoin::Network;
use clap::{App, Arg, ArgMatches};
use url::Url;

use lnrod::admin;
use lnrod::config::Config;
use lnrod::logger::{parse_log_level, LOG_LEVEL_NAMES};
use lnrod::node::NodeBuildArgs;
use std::str::FromStr;
use lnrod::signer::SIGNER_NAMES;

fn main() -> Result<()> {
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
		)
		.arg(
			Arg::new("signer")
				.about("signer name")
				.long("signer")
				.possible_values(&SIGNER_NAMES)
				.default_value(SIGNER_NAMES[0])
				.takes_value(true)
		)
		.arg(Arg::new("dump-config").long("dump-config"));
	let matches = app.clone().get_matches();

	let config = if matches.is_present("config") {
		get_config(&matches, &matches.value_of_t("config").unwrap())
	} else {
		Config::default()
	};

	if matches.is_present("dump-config") {
		println!("{}", toml::to_string(&config).unwrap());
		return Ok(());
	}

	let data_dir = arg_value_or_config("datadir", &matches, &config.data_dir);

	let bitcoin_url =
		Url::parse(arg_value_or_config("bitcoin", &matches, &config.bitcoin_rpc).as_str())?;

	// Network is regtest if specified on the command line or in the config file
	let network = if matches.occurrences_of("regtest") > 0 || config.regtest.unwrap_or(false) {
		Network::Regtest
	} else {
		Network::Testnet
	};

	let console_log_level = parse_log_level(arg_value_or_config(
		"loglevelconsole",
		&matches,
		&config.log_level_console,
	))
	.expect("log-level-console");
	let disk_log_level =
		parse_log_level(arg_value_or_config("logleveldisk", &matches, &config.log_level_disk))
			.expect("log-level-disk");

	let peer_listening_port = arg_value_or_config("lnport", &matches, &config.ln_port);
	let rpc_port = arg_value_or_config("rpcport", &matches, &config.rpc_port);

	let signer_name = arg_value_or_config("signer", &matches, &config.signer);

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
		signer_name,
		config,
	};

	admin::driver::start(rpc_port, args).expect("gRPC driver start");
	Ok(())
}

fn arg_value_or_config<T: Clone + FromStr>(
	name: &str, matches: &ArgMatches, config_value: &Option<T>,
) -> T
where
	<T as FromStr>::Err: std::fmt::Display,
{
	let arg = matches.value_of_t_or_exit(name);
	if matches.occurrences_of("datadir") > 0 {
		arg
	} else {
		config_value.clone().unwrap_or(arg)
	}
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
