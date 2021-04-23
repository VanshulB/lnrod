use crate::keys::{DynKeysInterface, DynSigner};
use bitcoin::hashes::hex::FromHex;
use bitcoin::{BlockHash, Txid};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::transaction::OutPoint;
use lightning::util::logger::Level as LogLevel;
use lightning::util::logger::{Logger, Record};
use lightning::util::ser::ReadableArgs;
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;

pub(crate) struct FilesystemLogger {
	data_dir: String,
	disk_log_level: LogLevel,
	console_log_level: LogLevel,
}
impl FilesystemLogger {
	pub(crate) fn new(
		data_dir: String, disk_log_level: LogLevel, console_log_level: LogLevel,
	) -> Self {
		let logs_path = format!("{}/logs", data_dir);
		fs::create_dir_all(logs_path.clone()).unwrap();
		Self { data_dir: logs_path, disk_log_level, console_log_level }
	}
}
impl Logger for FilesystemLogger {
	fn log(&self, record: &Record) {
		if self.console_log_level < record.level && self.disk_log_level < record.level {
			// Bail quickly if below current logging thresholds
			return;
		}
		let raw_log = record.args.to_string();
		let log = format!(
			"{} {:<5} [{}:{}] {}\n",
			OffsetDateTime::now_utc().format("%F %T"),
			record.level.to_string(),
			record.module_path,
			record.line,
			raw_log
		);
		if self.disk_log_level >= record.level {
			let logs_file_path = format!("{}/logs.txt", self.data_dir.clone());
			fs::OpenOptions::new()
				.create(true)
				.append(true)
				.open(logs_file_path)
				.unwrap()
				.write_all(log.as_bytes())
				.unwrap();
		}
		if self.console_log_level >= record.level {
			print!("{}", &log);
		}
	}
}
pub(crate) fn read_channelmonitors(
	path: String, keys_manager: Arc<DynKeysInterface>,
) -> Result<HashMap<OutPoint, (BlockHash, ChannelMonitor<DynSigner>)>, std::io::Error> {
	if !Path::new(&path).exists() {
		return Ok(HashMap::new());
	}
	let mut outpoint_to_channelmonitor = HashMap::new();
	for file_option in fs::read_dir(path).unwrap() {
		let file = file_option.unwrap();
		let owned_file_name = file.file_name();
		let filename = owned_file_name.to_str();
		if !filename.is_some() || !filename.unwrap().is_ascii() || filename.unwrap().len() < 65 {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Invalid ChannelMonitor file name",
			));
		}

		let txid = Txid::from_hex(filename.unwrap().split_at(64).0);
		if txid.is_err() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Invalid tx ID in filename",
			));
		}

		let index = filename.unwrap().split_at(65).1.split('.').next().unwrap().parse();
		if index.is_err() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Invalid tx index in filename",
			));
		}

		let contents = fs::read(&file.path())?;

		if let Ok((blockhash, channel_monitor)) = <(BlockHash, ChannelMonitor<DynSigner>)>::read(
			&mut Cursor::new(&contents),
			&*keys_manager,
		) {
			outpoint_to_channelmonitor.insert(
				OutPoint { txid: txid.unwrap(), index: index.unwrap() },
				(blockhash, channel_monitor),
			);
		} else {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Failed to deserialize ChannelMonitor",
			));
		}
	}
	Ok(outpoint_to_channelmonitor)
}
