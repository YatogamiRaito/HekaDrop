//! Ortak test yardımcıları — protokol-seviyesi entegrasyon testlerinde paylaşılır.
//!
//! HekaDrop binary-only bir crate (lib.rs yok). Bu yüzden `tests/` altındaki
//! entegrasyon testleri `hekadrop::...` erişemez; bunun yerine aynı dış crate'leri
//! (p256, aes, cbc, hmac, sha2, hkdf, prost) kullanarak protokol uyumluluğunu
//! bağımsızca doğrularız. Bu yaklaşımın bir yan faydası var: implement ve test
//! farklı yerlerden türetildiği için regresyonlar "yanlışı yanlışa eşitleyerek"
//! kaçırılmaz.
//!
//! Her test binary'si bu modülü `mod common;` ile include eder, ama kendi özel
//! fonksiyonlarını kullanır — kullanılmayan helper'lar dead_code warning'e yol
//! açabilir. `#[allow(dead_code)]` her yardımcıyı bireysel olarak bu beklenen
//! durumdan muaf tutar.

#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HKDF-SHA256 → HekaDrop `crypto::hkdf_sha256` ile birebir aynı davranış.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}

/// SHA256 tek seferlik.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Quick Share UKEY2 D2D sabit salt'ı — protokol sürümleri arası değişmez.
/// `src/crypto.rs::D2D_SALT` ile birebir eşleşmeli.
pub const D2D_SALT: [u8; 32] = [
    0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
    0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
];

/// Quick Share 4-haneli PIN türetme — `src/crypto.rs::pin_code_from_auth_key`
/// referans implementasyonunun birebir kopyası (NearDrop algoritması).
/// Her bayt Java'daki `byte`-olarak (signed) yorumlanır.
pub fn pin_code_from_auth_key(key: &[u8]) -> String {
    let mut hash: i64 = 0;
    let mut mult: i64 = 1;
    const MOD: i64 = 9973;
    for &b in key {
        let signed = b as i8 as i64;
        hash = (hash + signed * mult).rem_euclid(MOD);
        mult = (mult * 31).rem_euclid(MOD);
    }
    format!("{:04}", hash.abs())
}

/// Java `BigInteger.toByteArray()` uyumlu signed-byte formatı.
/// MSB ≥ 0x80 ise başa 0x00 eklenir (negatif yorumlanmaması için).
/// `src/ukey2.rs::to_signed_bytes` ile aynı davranış — bağımsız implement.
pub fn to_signed_bytes(v: &[u8]) -> Vec<u8> {
    if !v.is_empty() && v[0] >= 0x80 {
        let mut out = Vec::with_capacity(v.len() + 1);
        out.push(0x00);
        out.extend_from_slice(v);
        out
    } else {
        v.to_vec()
    }
}
