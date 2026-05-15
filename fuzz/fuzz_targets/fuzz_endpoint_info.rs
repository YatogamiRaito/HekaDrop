#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Mirrors discovery.rs parse() internal logic (private fn, inlined here)
    if data.len() < 17 {
        return;
    }
    let bitmap = data[0];
    let _device_type = (bitmap >> 1) & 0x07;

    if data.len() >= 18 {
        let name_len = data[17] as usize;
        if data.len() >= 18 + name_len && name_len > 0 {
            // UTF-8 decode — expect no panic
            let _ = String::from_utf8(data[18..18 + name_len].to_vec());
        }
    }
});
