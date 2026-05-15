#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use hekadrop_core::{
    location::nearby::connections::PayloadTransferFrame,
    payload::PayloadAssembler,
};

fuzz_target!(|data: &[u8]| {
    let Ok(pt) = PayloadTransferFrame::decode(data) else { return };

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio rt");
    let mut assembler = PayloadAssembler::new();
    let _ = rt.block_on(assembler.ingest(&pt));
});
