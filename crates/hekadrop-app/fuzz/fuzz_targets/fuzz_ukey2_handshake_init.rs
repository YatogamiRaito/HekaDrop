#![no_main]
//! Fuzz target: UKEY2 `ClientInit` parser (receiver role).
//!
//! `process_client_init` (re-exported from `hekadrop::ukey2`) wraps the full
//! decode + validation pipeline executed the first time a peer speaks to us:
//!
//!   1. `Ukey2Message::decode(raw)` — outer envelope
//!   2. `Ukey2ClientInit::decode(inner)` — payload
//!   3. version / random length / next_protocol / cipher_commitments count
//!      validation
//!   4. P-256 ECDH key generation on success
//!
//! This is the first frame an unauthenticated attacker controls end-to-end,
//! so any panic here is a pre-auth DoS. An error return (protocol mismatch,
//! decode failure) is the correct outcome — only panics or UB fail the
//! harness.
//!
//! Note: on valid inputs this triggers `SecretKey::random(&mut OsRng)`, which
//! involves a syscall. libfuzzer handles this fine but throughput will drop
//! on well-formed seeds; that's acceptable for scaffolding.

use hekadrop::process_client_init;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = process_client_init(data);
});
