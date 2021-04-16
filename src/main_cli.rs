use clap::{App, Arg, ArgMatches};
use ldk_node::admin::cli::CLI;

fn make_node_subapp() -> App<'static> {
    App::new("node")
        .about("control a node")
        .subcommand(App::new("info").about("Get node information"))
}

fn node_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("info", _)) => cli.node_info()?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_node_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_channel_subapp() -> App<'static> {
    App::new("channel")
        .about("control channels")
        .subcommand(App::new("list").about("List channels"))
        .subcommand(App::new("new").about("New channel")
            .arg(Arg::new("nodeid").about("node ID in hex"))
            .arg(Arg::new("address").about("host:port"))
            .arg(Arg::new("value").about("value in satoshi"))
            .arg(Arg::new("public").short('b').long("public").about("announce the channel"))
        )
}

fn channel_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("list", _)) => cli.channel_list()?,
        Some(("new", submatches)) => {
            let node_id_hex: String = submatches.value_of_t("nodeid")?;
            let node_id = hex::decode(node_id_hex).expect("hex");
            let address: String = submatches.value_of_t("address")?;
            let value_sat_str: String = submatches.value_of_t("value")?;
            let value_sat= value_sat_str.parse()?;
            let is_public = submatches.is_present("public");
            cli.channel_new(node_id, address.as_str(), value_sat, is_public)?
        },
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_channel_subapp().print_help()?
        }
    };
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new("client")
        .about("a CLI utility which communicates with a running Lightning Signer server via gRPC")
        .arg(
            Arg::new("connect")
                .short('c')
                .long("connect")
                .default_value("http://[::1]:8801")
                .about("Connect to an address")
                .takes_value(true)
                .global(true)
        )
        .subcommand(App::new("ping"))
        .subcommand(make_node_subapp())
        .subcommand(make_channel_subapp())
        ;
    let matches = app.clone().get_matches();
    let cli = CLI::new(matches.value_of("connect").unwrap().to_string());
    match matches.subcommand() {
        None => app.print_help()?,
        Some(("ping", _)) => cli.ping()?,
        Some(("node", submatches)) => node_subcommand(&cli, submatches)?,
        Some(("channel", submatches)) => channel_subcommand(&cli, submatches)?,
        Some((name, _)) => panic!("unimplemented command {}", name),
    }
    Ok(())
}
