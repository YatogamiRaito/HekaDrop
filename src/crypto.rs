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
    hk.expand(info, &mut out)
        .expect("HKDF genişletme başarısız");
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
/// NearDrop algoritması birebir:
///   hash=0, mult=1
///   for b in key: hash = (hash + b_signed * mult) % 9973, mult = (mult * 31) % 9973
///   pin = abs(hash) 4 hane
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

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC anahtar boyu");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
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
