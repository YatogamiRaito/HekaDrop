use hekadrop_core::secure::SecureCtx;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let mut ctx = SecureCtx {
            encrypt_key: [0xABu8; 32],
            decrypt_key: [0xCDu8; 32],
            send_hmac_key: [0xEFu8; 32],
            recv_hmac_key: [0x12u8; 32],
            server_seq: 0,
            client_seq: 0,
        };
        let _ = ctx.decrypt(data);
    });
}
