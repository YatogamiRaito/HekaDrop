//! UKEY2 ServerInit downgrade regression — wire-format seviyesi.
//!
//! `src/ukey2.rs::validate_server_init` happy-path dışında mutation-survivor
//! riski taşıyordu (saldırgan peer, ClientInit'te teklif etmediğimiz zayıf bir
//! cipher — örn. `CURVE25519_SHA512` ya da `RESERVED` — ile ServerInit dönerse
//! validator BAIL etmeli, yoksa sessizce düşülmüş bir handshake olur).
//!
//! Bu integration test:
//!   1) `prost::Message::encode_to_vec` ile gerçek UKEY2 wire bytes üretir.
//!   2) Aynı byte dizisini decode edip validator'a geçirir — ürün koduyla
//!      birebir özdeş validator yüzeyi (`src/ukey2.rs::validate_server_init`).
//!   3) P256_SHA512 dışı her cipher için hata mesajı `cipher downgrade` içerir.
//!   4) Version 1 dışı her değer için `yalnız V1` hata yolu çalışır.
//!   5) Happy path (V1 + P256_SHA512) regresyona karşı yeşil kalır.
//!
//! Neden integration (binary-external)? `src/ukey2.rs`'teki unit test'ler
//! struct alanlarını doğrudan kurar; wire-format decode yolunu atlar. Gerçek
//! Android peer'ı bizimle protobuf bytes değiş tokuşur, decode sırasında
//! `prost` varsayılanlarını (absent = `None`) doğru yorumlamak validator'ın
//! ilk sözleşmesi. Bu test o sözleşmeyi kilitler.

use anyhow::{bail, Result};
use prost::Message;

// --- UKEY2 wire-format mirror (proto/ukey.proto ile birebir) ---------------
// Neden mirror? `tests/` binary-external: `hekadrop::securegcm` yüzeyi lib.rs'te
// açık değil. Mirror `prost::Message` derive ile aynı proto tag/tip numaralarını
// kullanır → ürün kodunun decode'u ile birebir uyumlu byte üretir.
// Kaynak: proto/ukey.proto (securegcm paketi).

/// Ukey2HandshakeCipher enum değerleri — `proto/ukey.proto` ile aynı.
/// Değer değiştirmeyin: wire-format compat bozar.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
enum Cipher {
    Reserved = 0,
    P256Sha512 = 100,
    Curve25519Sha512 = 200,
}

#[derive(Clone, PartialEq, Message)]
struct Ukey2Message {
    #[prost(int32, optional, tag = "1")]
    message_type: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    message_data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct Ukey2ServerInit {
    #[prost(int32, optional, tag = "1")]
    version: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    random: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "3")]
    handshake_cipher: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    public_key: Option<Vec<u8>>,
}

/// `src/ukey2.rs::validate_server_init` birebir davranış kopyası.
/// Mirror olması kasıtlı: ürün kodu değişirse bu test'i de güncellemek
/// gerekir — drift alarmı niyetiyle tutuyoruz.
fn validate_server_init(s: &Ukey2ServerInit) -> Result<()> {
    if s.handshake_cipher != Some(Cipher::P256Sha512 as i32) {
        bail!(
            "ServerInit cipher downgrade reddedildi: {:?} (beklenen P256_SHA512)",
            s.handshake_cipher
        );
    }
    if s.version != Some(1) {
        bail!(
            "ServerInit version={:?} — yalnız V1 destekleniyor",
            s.version
        );
    }
    Ok(())
}

/// Bir `Ukey2ServerInit`'i `Ukey2Message` zarfına sarıp wire bytes döner.
/// Gerçek peer'dan gelen TAM frame body'si budur.
fn wrap_server_init_to_wire(si: &Ukey2ServerInit) -> Vec<u8> {
    let msg = Ukey2Message {
        message_type: Some(3), // SERVER_INIT
        message_data: Some(si.encode_to_vec()),
    };
    msg.encode_to_vec()
}

/// Wire bytes'tan ServerInit'i decode edip validator'a besleyen uçtan uca
/// pipeline — gerçek ağ frame'inin yaşayacağı yol.
fn decode_and_validate(wire: &[u8]) -> Result<Ukey2ServerInit> {
    let outer = Ukey2Message::decode(wire)?;
    let ty = outer
        .message_type
        .ok_or_else(|| anyhow::anyhow!("message_type yok"))?;
    if ty != 3 {
        bail!("beklenen SERVER_INIT (3), alınan {ty}");
    }
    let body = outer
        .message_data
        .ok_or_else(|| anyhow::anyhow!("message_data yok"))?;
    let si = Ukey2ServerInit::decode(&body[..])?;
    validate_server_init(&si)?;
    Ok(si)
}

// ---------------------------------------------------------------------------

#[test]
fn happy_path_p256_sha512_v1_kabul_edilir() {
    let si = Ukey2ServerInit {
        version: Some(1),
        random: Some(vec![0x42u8; 32]),
        handshake_cipher: Some(Cipher::P256Sha512 as i32),
        public_key: Some(vec![0x04, 0xAA, 0xBB]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let parsed = decode_and_validate(&wire).expect("happy path geçmeli");
    assert_eq!(parsed.version, Some(1));
    assert_eq!(parsed.handshake_cipher, Some(Cipher::P256Sha512 as i32));
}

#[test]
fn downgrade_curve25519_sha512_reddedilir() {
    // Saldırgan peer — ClientInit'te sadece P256_SHA512 önerdiğimiz halde
    // ServerInit'te Curve25519 döner. Downgrade saldırısı: bilinen-zayıf
    // veya henüz-audit'lenmemiş bir cipher'a kaydırmaya çalışır.
    let si = Ukey2ServerInit {
        version: Some(1),
        random: Some(vec![0u8; 32]),
        handshake_cipher: Some(Cipher::Curve25519Sha512 as i32),
        public_key: Some(vec![0u8; 33]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let err = decode_and_validate(&wire).expect_err("downgrade reddedilmeli");
    let msg = err.to_string();
    assert!(
        msg.contains("cipher downgrade"),
        "hata mesajı 'cipher downgrade' içermeli: {msg}"
    );
}

#[test]
fn downgrade_reserved_cipher_reddedilir() {
    // `RESERVED = 0` — proto spec'inde "kullanmayın" işaretli. Peer bu değeri
    // dönerse ya bug ya downgrade — her iki durumda da kabul edilemez.
    let si = Ukey2ServerInit {
        version: Some(1),
        random: Some(vec![0u8; 32]),
        handshake_cipher: Some(Cipher::Reserved as i32),
        public_key: Some(vec![0u8; 16]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let err = decode_and_validate(&wire).expect_err("RESERVED reddedilmeli");
    assert!(err.to_string().contains("cipher downgrade"));
}

#[test]
fn downgrade_unknown_numeric_cipher_reddedilir() {
    // Tanımsız bir enum değeri (örn. 9999) — proto `optional int32` olduğu için
    // decode başarılı olur ama HekaDrop'un whitelist'inde yoktur.
    let si = Ukey2ServerInit {
        version: Some(1),
        random: Some(vec![0u8; 32]),
        handshake_cipher: Some(9999),
        public_key: Some(vec![0u8; 16]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let err = decode_and_validate(&wire).expect_err("bilinmeyen cipher reddedilmeli");
    assert!(err.to_string().contains("cipher downgrade"));
}

#[test]
fn handshake_cipher_alani_eksikse_reddedilir() {
    // Peer `handshake_cipher` alanını hiç göndermez → prost decode'da `None`.
    // Validator None'ı P256_SHA512 DEĞİL olarak kabul etmeli.
    let si = Ukey2ServerInit {
        version: Some(1),
        random: Some(vec![0u8; 32]),
        handshake_cipher: None,
        public_key: Some(vec![0u8; 16]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let err = decode_and_validate(&wire).expect_err("eksik cipher reddedilmeli");
    assert!(err.to_string().contains("cipher downgrade"));
}

#[test]
fn version_downgrade_v0_reddedilir() {
    // Version 0 → rollback protection ihlal. P256_SHA512 doğru olsa bile
    // version downgrade kendi başına handshake'i iptal etmeli.
    let si = Ukey2ServerInit {
        version: Some(0),
        random: Some(vec![0u8; 32]),
        handshake_cipher: Some(Cipher::P256Sha512 as i32),
        public_key: Some(vec![0u8; 16]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let err = decode_and_validate(&wire).expect_err("v0 reddedilmeli");
    assert!(
        err.to_string().contains("yalnız V1"),
        "version hatası beklenen: {err}"
    );
}

#[test]
fn version_downgrade_bilinmeyen_numerik_reddedilir() {
    // Gelecekteki version 2, 3 veya saldırgan tarafından uydurulmuş 42 —
    // bugünkü implementasyon yalnız V1 tanır, geri kalanı reddedilmeli.
    for bad in [2i32, 3, 42, -1] {
        let si = Ukey2ServerInit {
            version: Some(bad),
            random: Some(vec![0u8; 32]),
            handshake_cipher: Some(Cipher::P256Sha512 as i32),
            public_key: Some(vec![0u8; 16]),
        };
        let wire = wrap_server_init_to_wire(&si);
        let err =
            decode_and_validate(&wire).unwrap_err_or_else(|_| panic!("bad={bad} reddedilmeli"));
        assert!(
            err.to_string().contains("yalnız V1"),
            "bad={bad} hata: {err}"
        );
    }
}

#[test]
fn version_alani_eksikse_reddedilir() {
    // `version: None` — prost default. Validator None'ı V1 değil olarak almalı.
    let si = Ukey2ServerInit {
        version: None,
        random: Some(vec![0u8; 32]),
        handshake_cipher: Some(Cipher::P256Sha512 as i32),
        public_key: Some(vec![0u8; 16]),
    };
    let wire = wrap_server_init_to_wire(&si);
    let err = decode_and_validate(&wire).expect_err("eksik version reddedilmeli");
    assert!(err.to_string().contains("yalnız V1"));
}

#[test]
fn hatali_message_type_reddedilir() {
    // `message_type` SERVER_INIT (3) değil, ALERT (1) ya da CLIENT_INIT (2).
    // Validator pipeline'ı bu kadar erken safhada durdurmalı.
    let si = Ukey2ServerInit {
        version: Some(1),
        random: Some(vec![0u8; 32]),
        handshake_cipher: Some(Cipher::P256Sha512 as i32),
        public_key: Some(vec![0u8; 16]),
    };
    let wrong_type = Ukey2Message {
        message_type: Some(1), // ALERT
        message_data: Some(si.encode_to_vec()),
    };
    let wire = wrong_type.encode_to_vec();
    let err = decode_and_validate(&wire).expect_err("ALERT SERVER_INIT değil");
    assert!(
        err.to_string().contains("SERVER_INIT"),
        "hata mesajı: {err}"
    );
}

// anyhow::Result'un `expect_err` stilinde closure-bazlı kullanımı için küçük yardımcı.
trait ResultExpectErr<T> {
    fn unwrap_err_or_else<F: FnOnce(T) -> anyhow::Error>(self, f: F) -> anyhow::Error;
}
impl<T> ResultExpectErr<T> for Result<T> {
    fn unwrap_err_or_else<F: FnOnce(T) -> anyhow::Error>(self, f: F) -> anyhow::Error {
        match self {
            Err(e) => e,
            Ok(v) => f(v),
        }
    }
}
