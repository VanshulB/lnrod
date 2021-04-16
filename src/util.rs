use serde::Serializer;

pub fn as_hex<S>(buf: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    serializer.serialize_str(&hex::encode(&buf))
}

