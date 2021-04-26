use anyhow::Result;
use serde::Serializer;

pub fn as_hex<S>(buf: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&hex::encode(&buf))
}

pub fn as_payment_status<S>(status: &i32, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(match status {
		0 => "pending",
		1 => "succeeded",
		2 => "failed",
		_ => "unknown",
	})
}
