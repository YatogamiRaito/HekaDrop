#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hekadrop_core::ukey2::process_client_init(data);
});
