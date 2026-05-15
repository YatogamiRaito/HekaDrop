#![no_main]

use hekadrop_core::chunk_hmac::{build_chunk_integrity, compute_tag, verify_tag};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().expect("32 byte key");
    let payload_id = i64::from_be_bytes(data[32..40].try_into().expect("8 byte"));
    let body = &data[40..];

    // compute_tag → Result; large body returns Err(BodyTooLarge) — no panic
    let Ok(tag) = compute_tag(&key, payload_id, 0, 0, body) else {
        return;
    };
    let Ok(ci) = build_chunk_integrity(payload_id, 0, 0, body.len(), tag) else {
        return;
    };
    let _ = verify_tag(&key, &ci, body);

    // Mutated verify — wrong body, expect TagMismatch (no panic)
    if !body.is_empty() {
        let mut wrong = body.to_vec();
        wrong[0] ^= 0xFF;
        let _ = verify_tag(&key, &ci, &wrong);
    }
});
