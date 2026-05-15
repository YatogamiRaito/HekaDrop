#![no_main]

use libfuzzer_sys::fuzz_target;
use p256::SecretKey;
use hekadrop_core::ukey2::{process_client_finish, ServerInitResult};

fuzz_target!(|data: &[u8]| {
    // Fixed seed key (non-random, deterministic for reproducibility)
    let secret_bytes = [0x42u8; 32];
    let Ok(secret_key) = SecretKey::from_bytes((&secret_bytes).into()) else {
        return;
    };
    let state = ServerInitResult {
        server_init_bytes: vec![0u8; 32],
        secret_key,
        cipher_commitment: vec![0u8; 32],
        client_init_bytes: vec![0u8; 32],
    };
    let _ = process_client_finish(data, &state);
});
