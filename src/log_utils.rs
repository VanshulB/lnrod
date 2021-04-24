use anyhow::{anyhow, Result};

use lightning::util::logger::Level as LogLevel;

// Copied from lightning::util::logger due to insufficient visibility.
pub const LOG_LEVELS: [LogLevel; 6] = [
	LogLevel::Off, LogLevel::Error, LogLevel::Warn, LogLevel::Info, LogLevel::Debug, LogLevel::Trace
];

pub const LOG_LEVEL_NAMES: [&'static str; 6] = ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

pub fn parse_log_level(lvlstr: String) -> Result<LogLevel> {
	Ok(*LOG_LEVELS
		.iter()
		.find(|ll| lvlstr == ll.to_string())
		.ok_or_else(|| anyhow!("invalid log level: {}", lvlstr))?)
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
