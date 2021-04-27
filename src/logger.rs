use std::fmt;
use std::fmt::Pointer;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;

use lightning::util::logger::Level as LogLevel;
use lightning::util::logger::Record;

// Copied from lightning::util::logger due to insufficient visibility.
pub const LOG_LEVELS: [LogLevel; 6] = [
	LogLevel::Off,
	LogLevel::Error,
	LogLevel::Warn,
	LogLevel::Info,
	LogLevel::Debug,
	LogLevel::Trace,
];

pub const LOG_LEVEL_NAMES: [&'static str; 6] = ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

pub fn parse_log_level(lvlstr: String) -> Result<LogLevel> {
	Ok(*LOG_LEVELS
		.iter()
		.find(|ll| lvlstr == ll.to_string())
		.ok_or_else(|| anyhow!("invalid log level: {}", lvlstr))?)
}

pub struct AbstractLogger {
	logger: Box<dyn lightning::util::logger::Logger>,
}
impl AbstractLogger {
	pub fn new(logger: Box<dyn lightning::util::logger::Logger>) -> AbstractLogger {
		AbstractLogger { logger }
	}
}
impl lightning::util::logger::Logger for AbstractLogger {
	fn log(&self, record: &Record) {
		self.logger.log(record);
	}
}
impl fmt::Debug for AbstractLogger {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.logger.fmt(f)
	}
}

static SINGLETON: OnceCell<Arc<AbstractLogger>> = OnceCell::new();

pub(crate) fn set(logger: Arc<AbstractLogger>) {
	SINGLETON.set(logger).unwrap();
}

pub(crate) fn get() -> Arc<AbstractLogger> {
	SINGLETON.get().expect("logger instance not initialized").clone()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn check_parse_log_level(lvlstr: &str, level: LogLevel) {
		assert_eq!(parse_log_level(lvlstr.to_string()).unwrap(), level);
	}

	#[test]
	fn test_good_log_levels() {
		check_parse_log_level("OFF", LogLevel::Off);
		check_parse_log_level("ERROR", LogLevel::Error);
		check_parse_log_level("WARN", LogLevel::Warn);
		check_parse_log_level("INFO", LogLevel::Info);
		check_parse_log_level("DEBUG", LogLevel::Debug);
		check_parse_log_level("TRACE", LogLevel::Trace);
	}

	#[test]
	fn test_bad_log_levels() {
		assert_error_string!(parse_log_level("BAD".to_string()), "invalid log level: BAD");
	}
}
