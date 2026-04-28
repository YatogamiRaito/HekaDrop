use std::io::Result;

fn main() -> Result<()> {
    let protos = [
        "proto/device_to_device_messages.proto",
        "proto/offline_wire_formats.proto",
        "proto/securegcm.proto",
        "proto/securemessage.proto",
        "proto/sharing_enums.proto",
        "proto/ukey.proto",
        "proto/wire_format.proto",
        // RFC-0003 §3.2: HekaDrop-only extension envelope
        // (capabilities, chunk_tag, resume_hint, resume_reject, folder_mft).
        // Wire layout: 4-byte BE magic (0xA5DEB201) + bu protobuf payload.
        // Dispatcher: hekadrop-core::frame.
        "proto/hekadrop_extensions.proto",
    ];

    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }
    println!("cargo:rerun-if-changed=build.rs");

    // Dalga 2: hot-path Bytes refactor — tüm `bytes` alanları prost tarafından
    // `bytes::Bytes` olarak generate edilir (zero-copy reference semantics).
    let mut cfg = prost_build::Config::new();
    cfg.bytes(["."]);
    cfg.compile_protos(&protos, &["proto"])?;
    Ok(())
}
