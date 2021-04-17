const SERDE_SERIALIZE_HEX: &'static str = "#[serde(serialize_with = \"crate::util::as_hex\")]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .format(false)
        .type_attribute(".", "#[derive(serde::Serialize)]")
        .field_attribute("peer_node_id", SERDE_SERIALIZE_HEX)
        .field_attribute("channel_id", SERDE_SERIALIZE_HEX)
        .field_attribute("node_id", SERDE_SERIALIZE_HEX)
        .out_dir("src/admin")
        .compile(&["src/admin/admin.proto"], &["src/admin"])?;
    Ok(())
}
