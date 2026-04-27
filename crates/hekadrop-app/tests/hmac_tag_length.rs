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

//! HMAC tag uzunluk doğrulaması — peer kısa (veya uzun) tag göndererek
//! `subtle::ConstantTimeEq::ct_eq`'in "uzunluk farklıysa sessiz false" davranışına
//! yaslanamamalı. `SecureCtx::decrypt` böyle bir frame'i *açıkça* reddetmeli.
//!
//! Güvenlik araştırması bulgusu: HMAC-SHA256 her zaman 32 bayt üretir. Peer'dan
//! gelen `SecureMessage.signature` farklı uzunluktaysa bu protokol ihlali ve
//! muhtemelen bir truncation / tag-length confusion denemesi. Erken bail
//! uzunluk-confusion sınıfı saldırılara karşı defense-in-depth.
//!
//! İlgili guard'lar:
//!   * `src/secure.rs::SecureCtx::decrypt` — HMAC doğrulamadan ÖNCE uzunluk check
//!   * `src/crypto.rs::hmac_sha256_verify` — defansif `tag.len() != 32 → false`

use hekadrop::secure::SecureCtx;
use hekadrop::securemessage::SecureMessage;
use hekadrop::DerivedKeys;
use prost::Message;

fn derived_keys_fixed() -> DerivedKeys {
    // Deterministik test anahtarları — gerçek HKDF burada ilgisiz, önemli olan
    // enc/hmac çiftlerinin iki yön arasında eşleşmesi (A.send = B.recv).
    DerivedKeys {
        decrypt_key: [11u8; 32],
        recv_hmac_key: [22u8; 32],
        encrypt_key: [33u8; 32],
        send_hmac_key: [44u8; 32],
        auth_key: [55u8; 32],
        pin_code: "0000".to_string(),
    }
}

/// Geçerli bir `SecureMessage` frame'i kur, sonra `signature`'ı kısaltarak
/// (31 bayt) `decrypt` çağır. Guard olmadan `ct_eq` sessiz false döner ve
/// hata "HMAC eşleşmedi" olurdu — ama spesifik uzunluk hatası istiyoruz
/// (log & metric ayrımı için).
#[test]
fn decrypt_rejects_short_hmac_tag() {
    // Eşleşmiş anahtar çifti: A gönderir, B alır.
    let keys_a = DerivedKeys {
        decrypt_key: [33u8; 32],
        recv_hmac_key: [44u8; 32],
        encrypt_key: [11u8; 32],
        send_hmac_key: [22u8; 32],
        auth_key: [55u8; 32],
        pin_code: "0000".to_string(),
    };
    let keys_b = derived_keys_fixed();

    let mut a = SecureCtx::from_keys(&keys_a);
    let mut b = SecureCtx::from_keys(&keys_b);

    // Önce geçerli bir roundtrip yap — elimizde gerçek bir encoded frame olsun.
    let valid_frame = a.encrypt(b"payload").expect("encrypt ok");
    let smsg = SecureMessage::decode(&valid_frame[..]).expect("decode valid");
    assert_eq!(smsg.signature.len(), 32, "baseline: tam 32 bayt HMAC");

    // Signature'ı 31 bayta kısalt — geri kalan frame aynı.
    let mut tampered = SecureMessage {
        header_and_body: smsg.header_and_body.clone(),
        signature: smsg.signature.slice(0..31),
    };
    assert_eq!(tampered.signature.len(), 31);
    let short_bytes = tampered.encode_to_vec();

    let err = b
        .decrypt(&short_bytes)
        .expect_err("31-bayt tag reddedilmeli");
    let msg = format!("{}", err);
    assert!(
        msg.contains("HMAC tag") || msg.contains("tag uzunluğu"),
        "uzunluk hatası beklenir, alınan: {}",
        msg
    );

    // İstemci seq'i advance etmemeli — state bozulmamalı, retry desteklenebilir.
    // (`b` decrypt'ten önce 0'dı, hata sonrası da 0 olmalı.)
    assert_eq!(
        b.client_seq, 0,
        "başarısız tag-length guard sonrası client_seq ilerlememeli"
    );

    // Kontrol: başka uzunluklar da reddedilmeli (33 bayt — fazla bayt ekleme).
    tampered.signature = {
        let mut v = smsg.signature.to_vec();
        v.push(0x00);
        v.into()
    };
    assert_eq!(tampered.signature.len(), 33);
    let long_bytes = tampered.encode_to_vec();
    assert!(
        b.decrypt(&long_bytes).is_err(),
        "33-bayt tag da reddedilmeli"
    );

    // Sıfır-bayt tag — degenerate case.
    tampered.signature = bytes::Bytes::new();
    let empty_bytes = tampered.encode_to_vec();
    assert!(b.decrypt(&empty_bytes).is_err(), "0-bayt tag reddedilmeli");
}

/// `hmac_sha256_verify` fonksiyonunun kendisi de yanlış uzunlukta tag'e
/// direkt `false` dönmeli — caller-side guard olsa bile defense-in-depth.
#[test]
fn hmac_verify_rejects_wrong_tag_length() {
    let key = [0x42u8; 32];
    let data = b"some message";
    let full_tag = hekadrop::crypto::hmac_sha256(&key, data);

    // Baseline: tam uzunluk kabul.
    assert!(hekadrop::crypto::hmac_sha256_verify(&key, data, &full_tag));

    // 31 bayt → false.
    assert!(!hekadrop::crypto::hmac_sha256_verify(
        &key,
        data,
        &full_tag[..31]
    ));

    // 33 bayt → false.
    let mut too_long = full_tag.to_vec();
    too_long.push(0x00);
    assert!(!hekadrop::crypto::hmac_sha256_verify(&key, data, &too_long));

    // 0 bayt → false.
    assert!(!hekadrop::crypto::hmac_sha256_verify(&key, data, &[]));
}
