use crate::signer::keys::{DynKeysInterface, DynSigner};
use anyhow::Result;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{BlockHash, Txid};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::transaction::OutPoint;
use lightning::util::ser::ReadableArgs;
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

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
