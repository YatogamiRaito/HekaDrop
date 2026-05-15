#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use hekadrop_proto::hekadrop_ext::{
    ChunkIntegrity, FolderManifest, HekaDropFrame, ResumeHint,
};

fuzz_target!(|data: &[u8]| {
    let _ = HekaDropFrame::decode(data);
    let _ = ChunkIntegrity::decode(data);
    let _ = ResumeHint::decode(data);
    let _ = FolderManifest::decode(data);
});
