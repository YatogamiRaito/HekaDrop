#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use hekadrop_core::location::nearby::connections::{
    PayloadTransferFrame,
    payload_transfer_frame::{PayloadChunk, PayloadHeader},
};

fuzz_target!(|data: &[u8]| {
    let _ = PayloadTransferFrame::decode(data);
    let _ = PayloadHeader::decode(data);
    let _ = PayloadChunk::decode(data);
});
