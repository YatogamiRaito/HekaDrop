//! M#7 — FileMetadata.size defense-in-depth guard regression.
//!
//! Saldırgan protobuf `FileMetadata.size` alanına negatif ya da absürt
//! büyük değer koyarsa:
//!   * negatif → Introduction aşamasında 0'a clamp (UI cosmetic fix)
//!   * `MAX_FILE_BYTES` (1 TiB) üstü → Introduction reddedilir, peer'a
//!     `Cancel` frame yollanır
//!
//! Bu test pür sınıflandırma mantığını doğrular; TCP/UKEY2 full handshake
//! olmadan karar fonksiyonu izole edilir (aynı pattern: `trust_hijack.rs`).
//! `src/connection.rs` içindeki Introduction handler bu modülü çağırır —
//! mantık değişirse bu test refactor'ı yakalar.

use hekadrop::file_size_guard::{classify_file_size, FileSizeGuard, MAX_FILE_BYTES};

#[test]
fn case1_negatif_size_clamped() {
    assert_eq!(classify_file_size(-1), FileSizeGuard::Clamped);
    assert_eq!(classify_file_size(-1_000_000), FileSizeGuard::Clamped);
    assert_eq!(classify_file_size(i64::MIN), FileSizeGuard::Clamped);
}

#[test]
fn case2_i64_max_reject() {
    assert_eq!(classify_file_size(i64::MAX), FileSizeGuard::Reject);
}

#[test]
fn case3_one_tib_plus_reject() {
    // Tam 1 TiB kabul (sınır dahil); üstü red.
    assert_eq!(
        classify_file_size(MAX_FILE_BYTES),
        FileSizeGuard::Accept(MAX_FILE_BYTES)
    );
    assert_eq!(
        classify_file_size(MAX_FILE_BYTES + 1),
        FileSizeGuard::Reject
    );
    // Task spec: `size = 1 << 40` → yani **tam** 1 TiB. Sınır dahildir
    // (pratik Quick Share transferi asla 1 TiB'e yaklaşmaz; sınırın
    // kendisinde reject yapmak gereksiz katı). Üstü (1 << 40) + 1 reject.
    assert_eq!(
        classify_file_size(1i64 << 40),
        FileSizeGuard::Accept(1i64 << 40)
    );
    assert_eq!(classify_file_size((1i64 << 40) + 1), FileSizeGuard::Reject);
}

#[test]
fn case4_100mb_accept() {
    assert_eq!(
        classify_file_size(100_000_000),
        FileSizeGuard::Accept(100_000_000)
    );
}

#[test]
fn sifir_size_accept() {
    assert_eq!(classify_file_size(0), FileSizeGuard::Accept(0));
}

#[test]
fn max_file_sabiti_tam_olarak_1tib() {
    assert_eq!(MAX_FILE_BYTES, 1_099_511_627_776);
    assert_eq!(MAX_FILE_BYTES, 1i64 << 40);
}

#[test]
fn ui_gosterilen_deger_dogrudan_accept_s_den_gelir() {
    // UI tarafında `FileSummary.size` negatifse "-5 GB" gösterir; guard
    // Clamped dönerse connection.rs 0'a override ediyor → UI asla negatif
    // görmez. Bu testin kontratı: clamp kararında boyut 0 olur.
    match classify_file_size(-42) {
        FileSizeGuard::Clamped => { /* UI'a 0 yazılmalı — bkz. connection.rs */ }
        other => panic!("negatif size Clamped beklenirdi, geldi: {:?}", other),
    }
}
