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
    ];

    for p in &protos {
        println!("cargo:rerun-if-changed={}", p);
    }
    println!("cargo:rerun-if-changed=build.rs");

    prost_build::compile_protos(&protos, &["proto"])?;
    Ok(())
}
