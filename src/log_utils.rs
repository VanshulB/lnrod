use anyhow::{anyhow, Result};

use lightning::util::logger::Level as LogLevel;

// Copied from lightning::util::logger due to insufficient visibility.
pub const LOG_LEVEL_NAMES: [&'static str; 6] = ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

pub fn parse_log_level(lvlstr: String) -> Result<LogLevel> {
	let ndx = LOG_LEVEL_NAMES
		.iter()
		.position(|ll| lvlstr == *ll)
		.ok_or_else(|| anyhow!("invalid log level: {}", lvlstr))?;
	match ndx {
		ndx if ndx == LogLevel::Off as usize => Ok(LogLevel::Off),
		ndx if ndx == LogLevel::Error as usize => Ok(LogLevel::Error),
		ndx if ndx == LogLevel::Warn as usize => Ok(LogLevel::Warn),
		ndx if ndx == LogLevel::Info as usize => Ok(LogLevel::Info),
		ndx if ndx == LogLevel::Debug as usize => Ok(LogLevel::Debug),
		ndx if ndx == LogLevel::Trace as usize => Ok(LogLevel::Trace),
		_ => panic!("log level name to enum botch"),
	}
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
