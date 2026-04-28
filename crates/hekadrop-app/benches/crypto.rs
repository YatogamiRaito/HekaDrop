// Test/bench dosyası — production lint'leri test idiomatik kullanımı bozmasın.
// Cast/clone family de gevşek: test verisi hardcoded, numerik safety burada
// odak değil; behavior validation odaklıyız.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::expect_fun_call,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::ignored_unit_patterns,
    clippy::use_self,
    clippy::trivially_copy_pass_by_ref,
    clippy::single_match_else,
    clippy::map_err_ignore
)]

//! Criterion benchmark — kripto sıcak yolu (AES-CBC, HMAC, HKDF,
//! `session_fingerprint`). 64 KiB tipik chunk boyutunu temsil ediyor.
//!
//! Çalıştırma: `cargo bench --bench crypto`
//! Derleme kontrolü (CI/pre-commit): `cargo bench --no-run`

use criterion::{criterion_group, criterion_main, Criterion};
use hekadrop::crypto;
use std::hint::black_box;

fn bench_aes_roundtrip(c: &mut Criterion) {
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let pt = vec![0x55u8; 64 * 1024]; // 64 KiB — typical chunk size
    c.bench_function("aes256_cbc_encrypt/64KiB", |b| {
        b.iter(|| crypto::aes256_cbc_encrypt(black_box(&key), black_box(&iv), black_box(&pt)))
    });
    let ct = crypto::aes256_cbc_encrypt(&key, &iv, &pt);
    c.bench_function("aes256_cbc_decrypt/64KiB", |b| {
        b.iter(|| crypto::aes256_cbc_decrypt(black_box(&key), black_box(&iv), black_box(&ct)))
    });
}

fn bench_hmac(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let data = vec![0xAAu8; 64 * 1024];
    c.bench_function("hmac_sha256/64KiB", |b| {
        b.iter(|| crypto::hmac_sha256(black_box(&key), black_box(&data)))
    });
}

fn bench_hkdf(c: &mut Criterion) {
    let ikm = [0x33u8; 32];
    let salt = [0x77u8; 32];
    c.bench_function("hkdf_sha256/32B-out", |b| {
        b.iter(|| {
            crypto::hkdf_sha256(
                black_box(&ikm),
                black_box(&salt),
                black_box(b"UKEY2 v1 auth"),
                32,
            )
        })
    });
}

fn bench_session_fingerprint(c: &mut Criterion) {
    let auth_key = [0xAAu8; 32];
    c.bench_function("session_fingerprint", |b| {
        b.iter(|| crypto::session_fingerprint(black_box(&auth_key)))
    });
}

criterion_group!(
    benches,
    bench_aes_roundtrip,
    bench_hmac,
    bench_hkdf,
    bench_session_fingerprint
);
criterion_main!(benches);
