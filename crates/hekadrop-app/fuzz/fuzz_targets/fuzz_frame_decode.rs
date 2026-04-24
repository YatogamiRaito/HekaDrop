#![no_main]
//! Fuzz target: `OfflineFrame` protobuf decoder.
//!
//! The wire-level `frame::read_frame` is a length-prefixed async reader on a
//! `TcpStream`; its framing logic is a `u32::from_be_bytes` + size bound,
//! nothing to fuzz in isolation. The real attack surface is the protobuf
//! parser that runs on every frame body once the length prefix is stripped.
//! That entry point in production is `OfflineFrame::decode(bytes)` — see
//! `src/connection.rs` (multiple call sites).
//!
//! The fuzzer must confirm the prost-generated decoder never panics or
//! trips UB on arbitrary input. A malformed frame is an expected error, not
//! a crash.

use hekadrop::location::nearby::connections::OfflineFrame;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Discard the Result — any decode outcome (Ok/Err) is acceptable; only
    // a panic or memory-safety violation would fail the harness.
    let _ = OfflineFrame::decode(data);
});
