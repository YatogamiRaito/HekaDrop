use prost::Message;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        // 1. Magic dispatch
        match hekadrop_core::frame::dispatch_frame_body(data) {
            hekadrop_core::frame::FrameKind::HekaDrop { inner } => {
                let _ = hekadrop_proto::hekadrop_ext::HekaDropFrame::decode(inner);
            }
            hekadrop_core::frame::FrameKind::Offline { body } => {
                let _ = hekadrop_core::location::nearby::connections::OfflineFrame::decode(body);
            }
        }

        // 2. Raw protobuf decode
        let _ = hekadrop_core::location::nearby::connections::OfflineFrame::decode(data);
        let _ = hekadrop_proto::hekadrop_ext::HekaDropFrame::decode(data);
    });
}
