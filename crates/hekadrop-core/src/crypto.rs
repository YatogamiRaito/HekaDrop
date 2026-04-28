//! UKEY2 ve Quick Share kripto yardımcıları — HKDF-SHA256, AES-256-CBC, HMAC-SHA256, PIN türetme.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    // INVARIANT: HKDF-SHA256 yalnızca `len > 255 * HashLen (= 8160 bayt)` için
    // başarısız olur; tüm caller'lar (UKEY2 key derivation, Quick Share session
    // keys) ≤32 bayt ister. Çağrı kontrat ihlali = programlama hatası.
    #[allow(clippy::expect_used)]
    hk.expand(info, &mut out)
        .expect("HKDF len > 255*32 invariant ihlali");
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Quick Share 4-haneli PIN: authKey 32 bayttan türetilir.
/// `NearDrop` algoritması birebir:
///   hash=0, mult=1
///   for b in key: hash = (hash + `b_signed` * mult) % 9973, mult = (mult * 31) % 9973
///   pin = abs(hash) 4 hane
pub fn pin_code_from_auth_key(key: &[u8]) -> String {
    let mut hash: i64 = 0;
    let mut mult: i64 = 1;
    const MOD: i64 = 9973;
    for &b in key {
        // SAFETY-CAST: NearDrop algoritması birebir uyumu için u8 → i8
        // signed reinterpretation (0..=255 → -128..=127) kasıtlı.
        // Quick Share PIN deterministik olmalı — bu cast'i değiştirmek
        // wire incompat eder.
        #[allow(clippy::cast_possible_wrap)]
        let signed = i64::from(b as i8);
        hash = (hash + signed * mult).rem_euclid(MOD);
        mult = (mult * 31).rem_euclid(MOD);
    }
    format!("{:04}", hash.abs())
}

/// Oturumun log-güvenli özeti: `auth_key`'in SHA-256 hash'inin ilk 6 hex
/// karakteri.
///
/// **Neden:** PIN sadece 4 basamak (10k olasılık); SHA-256 özeti bile
/// rainbow-table / brute-force ile saniyeler içinde geri döndürülür.
/// Log audit için bunun yerine UKEY2 handshake'ten türeyen `auth_key`
/// (256-bit entropi) kullanıyoruz — brute-force mümkün değil, fingerprint
/// sender + receiver log'larını handshake boyunca ilişkilendirmeye
/// yeter ama zayıf PIN uzayını hedef almaz.
pub fn session_fingerprint(auth_key: &[u8]) -> String {
    let digest = sha256(auth_key);
    hex::encode(&digest[..3]) // 6 hex karakter
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // INVARIANT: HMAC-SHA256 spec'i (RFC 2104) tüm key uzunluklarını kabul eder
    // (kısa key zero-pad'lenir, uzun key SHA-256'dan geçer). `new_from_slice`
    // dökümante edilmiş olarak hiçbir koşulda fail etmez — yalnız trait
    // signature uniformluğu için Result döner.
    #[allow(clippy::expect_used)]
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 her key uzunluğunu kabul eder");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    // SECURITY: `ct_eq` eşit-olmayan slice'larda sessiz false döner. Erken ve
    // açık reddedip caller'ın bu durumu ayırt edebilmesini (ve log/metric'e
    // yansıtılmasını) sağlamak için uzunluk guard'ı en başta. HMAC-SHA256 tag
    // her zaman 32 bayt — başka bir değer protokol ihlali.
    if tag.len() != 32 {
        return false;
    }
    let computed = hmac_sha256(key, data);
    computed.ct_eq(tag).into()
}

pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    Aes256CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

pub fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, cipher::block_padding::UnpadError> {
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
}

/// D2D key derivation sonrası secure-message HMAC salt'ı: SHA256("SecureMessage").
pub fn secure_message_salt() -> [u8; 32] {
    sha256(b"SecureMessage")
}

/// Quick Share UKEY2 → D2D sabit salt'ı.
pub const D2D_SALT: [u8; 32] = [
    0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
    0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_code_deterministic() {
        let key = [0x42u8; 32];
        let pin = pin_code_from_auth_key(&key);
        assert_eq!(pin.len(), 4);
    }

    /// `NearDrop` referans PIN algoritmasına birebir KAT (known-answer test).
    ///
    /// Beklenen değerler `NearDrop` spec'indeki aynı akışı Python ile bağımsız
    /// olarak koşturup çıkarıldı:
    /// ```python
    /// def pin(key):
    ///     h, m, MOD = 0, 1, 9973
    ///     for b in key:
    ///         s = b if b < 128 else b - 256
    ///         h = (h + s * m) % MOD
    ///         m = (m * 31) % MOD
    ///     return f"{abs(h):04d}"
    /// ```
    ///
    /// Her vektör farklı bir mutation'u yakalar:
    ///   * `hash = hash - signed*mult` (operatör flip)
    ///   * `mult * 29` yerine `* 31` (sabit değişikliği)
    ///   * `rem_euclid` yerine `%` (işaretli/işaretsiz fark)
    ///   * `b as i8` yerine `b as i32` (signedness kaybı — [0xFF;32] vektörü
    ///     negatif byte'ları teste sokar)
    #[test]
    fn pin_matches_near_drop_algorithm_exactly() {
        // 0x01..=0x20 — signed byte yolu pozitif
        let k1: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        assert_eq!(pin_code_from_auth_key(&k1), "1631");

        // [0x42; 32] — mevcut determinism testinin gerçek beklenen değeri
        let k2 = [0x42u8; 32];
        assert_eq!(pin_code_from_auth_key(&k2), "0755");

        // [0xFF; 32] — signed byte yolu negatif; `b as i8` olmazsa sonuç değişir
        let k3 = [0xFFu8; 32];
        assert_eq!(pin_code_from_auth_key(&k3), "3464");

        // [0x00; 32] — edge case: hash hiç değişmez, 4-hane zero-pad kontrolü
        let k4 = [0x00u8; 32];
        assert_eq!(pin_code_from_auth_key(&k4), "0000");
    }

    /// Known-answer golden vector: 32-baytlık sabit bir `auth_key` → sabit 4-haneli PIN.
    ///
    /// Kapsam: yalnız `pin_code_from_auth_key` regression guard'ı — HKDF burada
    /// çalıştırılmıyor, test doğrudan sabit bir `auth_key` besliyor. Amaç, gelecekte
    /// `MOD=9973`, `mult*=31` çarpanı, `rem_euclid` ya da signed-byte yorumlaması
    /// **sessizce** değişirse bu testin kırılmasıyla fark edilsin. Mutation testing
    /// survivor'larını da kapatır (operatör flip, sabit değişikliği, signedness kaybı).
    ///
    /// HKDF → `auth_key` → PIN uçtan uca KAT testi ayrı bir vektör olarak eklenebilir;
    /// bu test özellikle PIN derivation adımını izole tutar.
    ///
    /// Kaynak: `NearDrop` referans algoritmasının Python'a birebir port'u ile bağımsız
    /// olarak türetildi (vektörü değiştirmek = algoritmayı değiştirmek).
    ///   <https://github.com/grishka/NearDrop> (PIN türetme Android paketinde benzer akış)
    ///
    /// **Bu vektör bir kez kaydedildi — gelecekte değişirse PIN derivation algoritması
    /// değişti demek, incele.** Değişiklik kasıtlıysa yeni beklenen PIN'i güncelle
    /// ve CHANGELOG'a düş.
    #[test]
    fn pin_code_known_vector_golden() {
        // Hex "auth_key" — 32 bayt, NearDrop test fixture stilinde sabit değer
        let auth_key =
            hex::decode("deadbeefcafef00d0123456789abcdef00112233445566778899aabbccddeeff")
                .expect("hex geçerli");
        assert_eq!(auth_key.len(), 32);
        // Python referansı:
        //   key = bytes.fromhex("deadbeef...ddeeff")
        //   h, m, MOD = 0, 1, 9973
        //   for b in key:
        //       s = b if b < 128 else b - 256
        //       h = (h + s*m) % MOD
        //       m = (m * 31) % MOD
        //   f"{abs(h):04d}"  →  "2544"
        let expected_pin = "2544";
        assert_eq!(pin_code_from_auth_key(&auth_key), expected_pin);
    }

    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let pt = b"merhaba dunya!!";
        let ct = aes256_cbc_encrypt(&key, &iv, pt);
        let dec = aes256_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_hmac_verify() {
        let k = [1u8; 32];
        let tag = hmac_sha256(&k, b"abc");
        assert!(hmac_sha256_verify(&k, b"abc", &tag));
        assert!(!hmac_sha256_verify(&k, b"abd", &tag));
    }

    #[test]
    fn test_hkdf_known_value() {
        // RFC 5869 A.1 test vector (IETF test vector for HKDF-SHA256)
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(okm, expected);
    }

    #[test]
    fn test_sha256_known() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let out = sha256(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(out.to_vec(), expected);
    }

    #[test]
    fn test_d2d_salt_sabit() {
        // Quick Share spec'inde sabit değer — protokol versiyonları arası değişmez.
        assert_eq!(D2D_SALT.len(), 32);
        assert_eq!(D2D_SALT[0], 0x82);
        assert_eq!(D2D_SALT[31], 0x10);
    }
}
