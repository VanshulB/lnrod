#[cfg(test)]
macro_rules! assert_error_string {
	($res: expr, $expected: expr) => {
		assert_eq!($res.err().unwrap().to_string(), $expected);
	};
}
