#![no_main]
//! Fuzz target: `SecureCtx::decrypt` on an attacker-controlled frame.
//!
//! Post-handshake, every message flows through `SecureCtx::decrypt` (see
//! `src/secure.rs`). Input path:
//!
//!   SecureMessage::decode(frame_bytes)
//!     → HMAC length check (must be 32)
//!     → HMAC-SHA256 verify against `recv_hmac_key`
//!     → HeaderAndBody::decode
//!     → IV length check (must be 16)
//!     → AES-256-CBC decrypt
//!     → DeviceToDeviceMessage::decode
//!     → sequence_number validation
//!
//! The fuzzer feeds arbitrary bytes in as `frame_bytes` with a zeroed key
//! context. The correct outcome for random data is `HmacMismatch` or a
//! decode error — never a panic.
//!
//! We fix the keys to zero (rather than letting the fuzzer pick them) because
//! the attacker in the real threat model doesn't control our keys; what they
//! do control is the ciphertext + HMAC tag + IV bytes, which is exactly what
//! `data` represents. Varying keys would only add entropy for no coverage
//! gain.
//!
//! `SecureCtx` fields are all `pub`, so direct struct literal construction
//! is used — the `#[cfg(test)] new_with_keys` helper isn't reachable from
//! the fuzz crate.

use hekadrop::secure::SecureCtx;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut ctx = SecureCtx {
        encrypt_key: [0u8; 32],
        decrypt_key: [0u8; 32],
        send_hmac_key: [0u8; 32],
        recv_hmac_key: [0u8; 32],
        server_seq: 0,
        client_seq: 0,
    };
    let _ = ctx.decrypt(data);
});
