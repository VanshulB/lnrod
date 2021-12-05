use crate::signer::keys::{DynKeysInterface, DynSigner};
use anyhow::Result;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{BlockHash, Txid};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::transaction::OutPoint;
use lightning::util::ser::{Readable, Writeable, ReadableArgs};
use lightning_signer::lightning;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use log::error;
use crate::NetworkGraph;

const MAX_CHANNEL_MONITOR_FILENAME_LENGTH: usize = 65;

pub(crate) fn read_channelmonitors(
	path: String, keys_manager: Arc<DynKeysInterface>,
) -> Result<HashMap<OutPoint, (BlockHash, ChannelMonitor<DynSigner>)>, std::io::Error> {
	if !Path::new(&path).exists() {
		return Ok(HashMap::new());
	}
	let mut outpoint_to_channelmonitor = HashMap::new();
	for file_option in fs::read_dir(path)? {
		let file = file_option?;
		let owned_file_name = file.file_name();
		let filename = owned_file_name.to_str().ok_or(std::io::Error::new(
			std::io::ErrorKind::Other,
			"Invalid ChannelMonitor file name: Not valid Unicode",
		))?;

		if !filename.is_ascii() || filename.len() < MAX_CHANNEL_MONITOR_FILENAME_LENGTH {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				format!(
					"Invalid ChannelMonitor file name: Must be ASCII with more than {} characters",
					MAX_CHANNEL_MONITOR_FILENAME_LENGTH
				),
			));
		}

		let txid = Txid::from_hex(filename.split_at(64).0).map_err(|_| {
			std::io::Error::new(std::io::ErrorKind::Other, "Invalid tx ID in filename")
		})?;

		let index = filename
			.split_at(MAX_CHANNEL_MONITOR_FILENAME_LENGTH)
			.1
			.split('.')
			.next()
			.unwrap()
			.parse()
			.map_err(|_| {
				std::io::Error::new(std::io::ErrorKind::Other, "Invalid tx index in filename")
			})?;

		let contents = fs::read(&file.path())?;

		if let Ok((blockhash, channel_monitor)) = <(BlockHash, ChannelMonitor<DynSigner>)>::read(
			&mut Cursor::new(&contents),
			&*keys_manager,
		) {
			outpoint_to_channelmonitor
				.insert(OutPoint { txid, index }, (blockhash, channel_monitor));
		} else {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Failed to deserialize ChannelMonitor",
			));
		}
	}
	Ok(outpoint_to_channelmonitor)
}

pub(crate) fn read_network(path: &Path, genesis_hash: BlockHash) -> NetworkGraph {
	if let Ok(file) = File::open(path) {
		if let Ok(graph) = NetworkGraph::read(&mut BufReader::new(file)) {
			return graph;
		}
	}
	NetworkGraph::new(genesis_hash)
}

pub(crate) fn persist_network(path: &Path, network_graph: &NetworkGraph) -> std::io::Result<()> {
	let mut tmp_path = path.to_path_buf().into_os_string();
	tmp_path.push(".tmp");
	let file = fs::OpenOptions::new().write(true).create(true).open(&tmp_path)?;
	let write_res = network_graph.write(&mut BufWriter::new(file));
	if let Err(e) = write_res.and_then(|_| fs::rename(&tmp_path, path)) {
		let _ = fs::remove_file(&tmp_path);
		Err(e)
	} else {
		Ok(())
	}
}

pub(crate) fn start_network_graph_persister(network_graph_path: String, network_graph: &Arc<NetworkGraph>) {
	let network_graph_persist = Arc::clone(&network_graph);
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(Duration::from_secs(600));
		loop {
			interval.tick().await;
			if persist_network(Path::new(&network_graph_path), &network_graph_persist)
				.is_err()
			{
				error!("Warning: Failed to persist network graph, check your disk and permissions");
			}
		}
	});
}
