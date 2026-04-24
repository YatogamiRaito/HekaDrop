#![no_main]
//! Fuzz target: `PayloadTransferFrame` + its nested `PayloadHeader`.
//!
//! The `PayloadAssembler::ingest` entry point in `src/payload.rs` receives an
//! already-decoded `PayloadTransferFrame`; the decoding itself happens one
//! layer up in `connection.rs` via `PayloadTransferFrame::decode(bytes)`.
//! This target exercises both:
//!
//!   1. The prost decoder (structural safety — must never panic on arbitrary
//!      input).
//!   2. The post-decode header accessors used by `PayloadAssembler`
//!      (`header.id`, `header.r#type`, `header.total_size`, and
//!      `chunk.flags/offset/body`). These are `Option` accessors, so no
//!      additional panic surface should exist — but walking every field once
//!      catches any future refactor that introduces `.unwrap()`.

use hekadrop::location::nearby::connections::PayloadTransferFrame;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = PayloadTransferFrame::decode(data) else {
        return;
    };

    // Touch every optional accessor used by PayloadAssembler::ingest so the
    // fuzzer catches panics introduced by future refactors (unwrap,
    // as_deref().unwrap(), arithmetic on i64 totals, etc.).
    if let Some(header) = frame.payload_header.as_ref() {
        let _ = header.id;
        let _ = header.r#type;
        let _ = header.total_size;
        let _ = header.is_sensitive;
        let _ = header.file_name.as_deref();
        let _ = header.parent_folder.as_deref();
        let _ = header.last_modified_timestamp_millis;
    }
    if let Some(chunk) = frame.payload_chunk.as_ref() {
        let _ = chunk.flags;
        let _ = chunk.offset;
        let _ = chunk.body.as_deref().map(|b| b.len());
        let _ = chunk.index;
    }
});
