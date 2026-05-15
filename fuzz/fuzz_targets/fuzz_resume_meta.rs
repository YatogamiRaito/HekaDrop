#![no_main]

use libfuzzer_sys::fuzz_target;
use hekadrop_core::resume;

fuzz_target!(|data: &[u8]| {
    // session_id_i64: SHA-256 of data → i64 (no panic expected)
    let sid = resume::session_id_i64(data);

    // meta_filename: safe string formatting
    if data.len() >= 8 {
        let payload_id = i64::from_be_bytes(data[..8].try_into().expect("8 byte"));
        let _ = resume::meta_filename(sid, payload_id);
    }
});
