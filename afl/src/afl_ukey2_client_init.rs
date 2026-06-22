fn main() {
    afl::fuzz!(|data: &[u8]| {
        let _ = hekadrop_core::ukey2::process_client_init(data);
    });
}
