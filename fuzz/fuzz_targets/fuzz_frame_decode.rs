#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // 1. Magic dispatch
    match hekadrop_core::frame::dispatch_frame_body(data) {
        hekadrop_core::frame::FrameKind::HekaDrop { inner } => {
            let _ = hekadrop_proto::hekadrop_ext::HekaDropFrame::decode(inner);
        }
        hekadrop_core::frame::FrameKind::Offline { body } => {
            let _ = hekadrop_core::location::nearby::connections::OfflineFrame::decode(body);
        }
    }

    // 2. Raw protobuf decode, her iki tip ile
    let _ = hekadrop_core::location::nearby::connections::OfflineFrame::decode(data);
    let _ = hekadrop_proto::hekadrop_ext::HekaDropFrame::decode(data);
});
