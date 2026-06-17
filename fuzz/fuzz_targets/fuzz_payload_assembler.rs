#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use hekadrop_core::{
    location::nearby::connections::PayloadTransferFrame,
    payload::PayloadAssembler,
};

fuzz_target!(|data: &[u8]| {
    let Ok(pt) = PayloadTransferFrame::decode(data) else { return };

    let mut assembler = PayloadAssembler::new();
    let _ = assembler.ingest(&pt);
});
