macro_rules! type_name {
	($tt: expr) => {{
		fn type_name_of<T>(_: &T) -> &'static str {
			std::any::type_name::<T>()
		}
		type_name_of($tt)
	}};
}

macro_rules! type_and_value {
	($vv: expr) => {{
		format!("{}={}", type_name!($vv), json!($vv))
	}};
}

macro_rules! log_internal {
	($lvl:expr, $($arg:tt)+) => (
		crate::logger::get().log(&lightning::util::logger::Record::new($lvl, format_args!($($arg)+), module_path!(), file!(), line!()));
	);
}

macro_rules! log_error {
	($($arg:tt)*) => ({
		#[cfg(not(any(feature = "max_level_off")))]
		    log_internal!(lightning::util::logger::Level::Error, $($arg)*);
    })
}

macro_rules! log_warn {
	($($arg:tt)*) => ({
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error")))]
		log_internal!(lightning::util::logger::Level::Warn, $($arg)*);
	})
}

macro_rules! log_info {
	($($arg:tt)*) => ({
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn")))]
		log_internal!(lightning::util::logger::Level::Info, $($arg)*);
	})
}

macro_rules! log_debug {
	($($arg:tt)*) => ({
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info")))]
		log_internal!(lightning::util::logger::Level::Debug, $($arg)*);
	})
}

macro_rules! log_trace {
	($($arg:tt)*) => ({
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug")))]
		log_internal!(lightning::util::logger::Level::Trace, $($arg)*);
	})
}
