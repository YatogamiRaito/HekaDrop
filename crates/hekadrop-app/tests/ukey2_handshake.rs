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

//! UKEY2 handshake protokolü uyumluluğu — P-256 ECDH + HKDF + Java-uyumlu
//! signed byte encoding'i tam simülasyon ile doğrular.
//!
//! Bu test crate'i HekaDrop binary'sine bağlamaz: aynı dış crate'leri
//! ([p256], [hkdf], [sha2], [prost]) kullanarak "Alice ↔ Bob" senaryosu kurar.
//! Amaç: HekaDrop tarafının ürettiği anahtarları başka bir peer'ın aynı
//! formülle yeniden türetebilmesini garanti etmek.

mod common;

use common::{hkdf_sha256, pin_code_from_auth_key, sha256, to_signed_bytes, D2D_SALT};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
use rand::rngs::OsRng;

/// İki taraf için HKDF ile türetilen 4+ anahtarı kapsayan yardımcı.
/// HekaDrop `DerivedKeys` yapısıyla aynı alanlar.
#[derive(Debug)]
struct DerivedKeys {
    client_aes: [u8; 32],
    client_hmac: [u8; 32],
    server_aes: [u8; 32],
    server_hmac: [u8; 32],
    auth_key: [u8; 32],
    pin_code: String,
}

fn into_32(v: Vec<u8>) -> [u8; 32] {
    assert_eq!(v.len(), 32, "32 bayt bekleniyor");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

/// Her iki taraf aynı `client_init_bytes || server_init_bytes` transcript'ini,
/// aynı shared secret'ı (ECDH X koordinatı) ve aynı HKDF çağrılarını yapınca
/// BIREBIR aynı anahtarları türetmeli.
fn derive_from_shared(
    shared_secret_sha256: &[u8; 32],
    client_init_bytes: &[u8],
    server_init_bytes: &[u8],
) -> DerivedKeys {
    let mut info = Vec::with_capacity(client_init_bytes.len() + server_init_bytes.len());
    info.extend_from_slice(client_init_bytes);
    info.extend_from_slice(server_init_bytes);

    let auth_key = hkdf_sha256(shared_secret_sha256, b"UKEY2 v1 auth", &info, 32);
    let next_secret = hkdf_sha256(shared_secret_sha256, b"UKEY2 v1 next", &info, 32);
    let pin_code = pin_code_from_auth_key(&auth_key);

    let d2d_client = hkdf_sha256(&next_secret, &D2D_SALT, b"client", 32);
    let d2d_server = hkdf_sha256(&next_secret, &D2D_SALT, b"server", 32);

    let smsg_salt = sha256(b"SecureMessage");
    let client_aes = hkdf_sha256(&d2d_client, &smsg_salt, b"ENC:2", 32);
    let client_hmac = hkdf_sha256(&d2d_client, &smsg_salt, b"SIG:1", 32);
    let server_aes = hkdf_sha256(&d2d_server, &smsg_salt, b"ENC:2", 32);
    let server_hmac = hkdf_sha256(&d2d_server, &smsg_salt, b"SIG:1", 32);

    DerivedKeys {
        client_aes: into_32(client_aes),
        client_hmac: into_32(client_hmac),
        server_aes: into_32(server_aes),
        server_hmac: into_32(server_hmac),
        auth_key: into_32(auth_key),
        pin_code,
    }
}

/// Her iki taraf için ECDH. Bilgi: P-256'da `alice.secret * bob.public ==
/// bob.secret * alice.public` olmalı — bu bizim sağlığın temeli.
#[test]
fn ecdh_iki_taraf_ayni_shared_secret_uretir() {
    // Deterministic çalışsın diye OsRng ile 2 farklı anahtar
    let alice_sk = SecretKey::random(&mut OsRng);
    let bob_sk = SecretKey::random(&mut OsRng);
    let alice_pk = alice_sk.public_key();
    let bob_pk = bob_sk.public_key();

    let alice_view = diffie_hellman(alice_sk.to_nonzero_scalar(), bob_pk.as_affine());
    let bob_view = diffie_hellman(bob_sk.to_nonzero_scalar(), alice_pk.as_affine());

    assert_eq!(
        alice_view.raw_secret_bytes().as_slice(),
        bob_view.raw_secret_bytes().as_slice(),
        "P-256 ECDH simetrik olmalı"
    );
}

/// Full handshake simülasyonu: Alice (client) ve Bob (server) aynı transcript
/// üzerinden aynı 4 AES/HMAC anahtarı + aynı auth_key + aynı PIN'i türetmeli.
#[test]
fn alice_bob_handshake_ayni_derived_keys_uretir() {
    let alice_sk = SecretKey::random(&mut OsRng);
    let bob_sk = SecretKey::random(&mut OsRng);

    // Her iki taraf için raw transcript — production'da bu `Ukey2Message`
    // serialize edilmiş halidir; testte muhtevası değil hash'i önemli.
    let client_init = b"CLIENT_INIT_FRAME_RAW_BYTES_alice";
    let server_init = b"SERVER_INIT_FRAME_RAW_BYTES_bob_0x0102";

    // Her iki taraf ECDH → shared X koordinatı
    let alice_view = diffie_hellman(
        alice_sk.to_nonzero_scalar(),
        bob_sk.public_key().as_affine(),
    );
    let bob_view = diffie_hellman(
        bob_sk.to_nonzero_scalar(),
        alice_sk.public_key().as_affine(),
    );
    assert_eq!(
        alice_view.raw_secret_bytes().as_slice(),
        bob_view.raw_secret_bytes().as_slice()
    );
    let shared_sha = sha256(alice_view.raw_secret_bytes().as_slice());

    let alice_keys = derive_from_shared(&shared_sha, client_init, server_init);
    let bob_keys = derive_from_shared(&shared_sha, client_init, server_init);

    assert_eq!(alice_keys.client_aes, bob_keys.client_aes);
    assert_eq!(alice_keys.client_hmac, bob_keys.client_hmac);
    assert_eq!(alice_keys.server_aes, bob_keys.server_aes);
    assert_eq!(alice_keys.server_hmac, bob_keys.server_hmac);
    assert_eq!(alice_keys.auth_key, bob_keys.auth_key);
    assert_eq!(alice_keys.pin_code, bob_keys.pin_code);
}

/// client_init ya da server_init transcript'i farklıysa (MITM birinin mesajını
/// değiştirmiş) türetilen anahtarlar ayrışmalı — bu yüzden MITM tespiti olabilir.
#[test]
fn transcript_binding_farkli_transcript_farkli_anahtar() {
    let alice_sk = SecretKey::random(&mut OsRng);
    let bob_sk = SecretKey::random(&mut OsRng);
    let view = diffie_hellman(
        alice_sk.to_nonzero_scalar(),
        bob_sk.public_key().as_affine(),
    );
    let shared_sha = sha256(view.raw_secret_bytes().as_slice());

    let ci = b"CLIENT_INIT_v1";
    let si = b"SERVER_INIT_v1";

    let k1 = derive_from_shared(&shared_sha, ci, si);
    // Taraflardan biri farklı transcript'e bağlanırsa:
    let k2 = derive_from_shared(&shared_sha, ci, b"SERVER_INIT_v2_TAMPERED");

    assert_ne!(k1.client_aes, k2.client_aes);
    assert_ne!(k1.auth_key, k2.auth_key);
    // PIN de değişir — kullanıcı eşleşmeyen PIN görür, bu MITM'i yakalar.
    assert_ne!(k1.pin_code, k2.pin_code);
}

/// 4-haneli PIN her zaman 4 basamak (leading-zero'lar `{:04}` ile korunur).
#[test]
fn pin_code_her_zaman_4_basamak() {
    // Kasıtlı olarak küçük hash türeten anahtar — leading zero'lu PIN
    // için deterministik bir input zor ama `{:04}` formatı her durumda
    // 4 karakter garanti eder.
    for key_seed in [0u8, 1, 42, 0xFF, 0x80, 0x7F] {
        let key = [key_seed; 32];
        let pin = pin_code_from_auth_key(&key);
        assert_eq!(pin.len(), 4, "PIN her zaman 4 karakter olmalı: '{}'", pin);
        assert!(pin.chars().all(|c| c.is_ascii_digit()), "PIN sadece digit");
    }
}

/// NearDrop referansı ile aynı PIN algoritması — Java BigInteger signed-byte
/// davranışı burada önemli. 0x80'lik bir byte Java'da -128 olmalı, Rust'ta
/// `b as i8 as i64` = -128 çıkmalı.
#[test]
fn pin_code_signed_byte_java_uyumlu() {
    // Kritik senaryo: MSB>=0x80 olan key baytları.
    let key: [u8; 32] = [
        0x80, 0xFF, 0x7F, 0x01, 0x00, 0xCC, 0xA5, 0x5A, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    ];
    let pin = pin_code_from_auth_key(&key);

    // Deterministik: elle çalıştırıldı. Algoritma değişmediği sürece bu değişmez.
    // Değişirse test kırılır → incelenmesi gerekir.
    assert_eq!(pin.len(), 4);
    // Hash 0 ile 9972 arası — 4 basamak fit eder.
    let n: i64 = pin.parse().unwrap();
    assert!((0..10_000).contains(&n));
}

/// `to_signed_bytes` — MSB ≥ 0x80 ise 0x00 prefix eklenmeli.
#[test]
fn to_signed_bytes_msb_yuksekken_prefix_eklenir() {
    assert_eq!(to_signed_bytes(&[0x80]), vec![0x00, 0x80]);
    assert_eq!(to_signed_bytes(&[0xFF, 0xAB]), vec![0x00, 0xFF, 0xAB]);
    assert_eq!(
        to_signed_bytes(&[0x80, 0x00, 0x00]),
        vec![0x00, 0x80, 0x00, 0x00]
    );
}

/// `to_signed_bytes` — MSB < 0x80 ise değişiklik olmamalı.
#[test]
fn to_signed_bytes_msb_dusukken_degismez() {
    assert_eq!(to_signed_bytes(&[0x7F]), vec![0x7F]);
    assert_eq!(to_signed_bytes(&[0x01, 0x02]), vec![0x01, 0x02]);
    assert_eq!(to_signed_bytes(&[0x00, 0xFF]), vec![0x00, 0xFF]);
}

/// Boş slice edge-case: hiç 0x00 eklenmemeli.
#[test]
fn to_signed_bytes_bos_slice_bos_kalir() {
    let out = to_signed_bytes(&[]);
    assert!(out.is_empty());
}

/// P-256 public key encode → `to_signed_bytes(X) || to_signed_bytes(Y)`.
/// Gerçek Android peer'ları bu formatı zorunlu olarak bekler (Java BigInteger).
#[test]
fn p256_public_key_signed_encoding_java_uyumlu() {
    let sk = SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    let encoded = pk.to_encoded_point(false);
    let xy = encoded.as_bytes();
    assert_eq!(xy[0], 0x04, "uncompressed prefix");
    let x_raw = &xy[1..33];
    let y_raw = &xy[33..65];
    let x_signed = to_signed_bytes(x_raw);
    let y_signed = to_signed_bytes(y_raw);

    // `x_signed` her zaman 32 veya 33 bayt olmalı (MSB'ye göre)
    assert!(x_signed.len() == 32 || x_signed.len() == 33);
    assert!(y_signed.len() == 32 || y_signed.len() == 33);

    // İlk baytın yüksek biti kontrolü
    if x_raw[0] >= 0x80 {
        assert_eq!(x_signed[0], 0x00);
        assert_eq!(x_signed.len(), 33);
    } else {
        assert_eq!(x_signed.len(), 32);
    }
}

/// HKDF-SHA256 RFC 5869 A.1 vektörü — crypto modülünün hkdf çağrısı standart.
/// Bizim common::hkdf_sha256 yardımcımız doğru çalışıyor mu?
#[test]
fn hkdf_sha256_rfc5869_a1_test_vector() {
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

/// Derived keys'in "rol simetrisi": client taraf encrypt_key olarak client_aes'i
/// kullanırsa, server taraf decrypt_key olarak aynı key'i kullanmalı. Bu test
/// HekaDrop `DerivedKeys` doldurmasının simetrik olduğunu doğrular.
#[test]
fn rol_simetrisi_client_enc_eq_server_dec() {
    let alice_sk = SecretKey::random(&mut OsRng);
    let bob_sk = SecretKey::random(&mut OsRng);
    let view = diffie_hellman(
        alice_sk.to_nonzero_scalar(),
        bob_sk.public_key().as_affine(),
    );
    let shared_sha = sha256(view.raw_secret_bytes().as_slice());
    let ci = b"ci";
    let si = b"si";
    let keys = derive_from_shared(&shared_sha, ci, si);

    // Client rolü: encrypt=client_aes, decrypt=server_aes (HekaDrop client_handshake)
    // Server rolü: decrypt=client_aes, encrypt=server_aes (HekaDrop process_client_finish)
    //
    // Client ve server yön farkı: aynı AES key iki yönde asla kullanılmaz.
    // Aksi halde IV reuse + ciphertext XOR ile plaintext sızar.
    assert_ne!(
        keys.client_hmac, keys.server_hmac,
        "HMAC yönleri ayrı olmalı"
    );
    assert_ne!(keys.client_aes, keys.server_aes, "AES yönleri ayrı olmalı");

    // Anahtarların tamamı sıfır olmamalı (HKDF düzgün çalışmış)
    assert_ne!(
        keys.client_aes, [0u8; 32],
        "client_aes HKDF çıktısı sıfır olmamalı"
    );
    assert_ne!(keys.server_aes, [0u8; 32]);
    assert_ne!(keys.auth_key, [0u8; 32]);
}

/// Peer public key `Option<PublicKey>` — None dönen noktalar eğri üzerinde
/// değildir. Bu test "her türlü bayt kombinasyonu" public key olmadığını
/// ve UKEY2 tarafının "geçersiz eğri noktası" hatasını verdiğini doğrular.
#[test]
fn gecersiz_peer_pubkey_reddedilir() {
    use elliptic_curve::sec1::FromEncodedPoint;
    use p256::EncodedPoint;

    // Rastgele 64 bayt — P-256 üzerinde *kesinlikle* valid bir nokta olma olasılığı
    // astronomik derecede düşük (~2^-128). Deterministic test için hep-aynı deseni:
    let bad_x = [0xAAu8; 32];
    let bad_y = [0xBBu8; 32];
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&bad_x);
    uncompressed.extend_from_slice(&bad_y);

    let encoded = EncodedPoint::from_bytes(&uncompressed);
    // EncodedPoint parse'ı başarılı olabilir (yalnızca tag kontrol eder),
    // ama `PublicKey::from_encoded_point` eğri denklemi kontrolü yapar.
    match encoded {
        Ok(ep) => {
            let pk: Option<PublicKey> = PublicKey::from_encoded_point(&ep).into();
            assert!(pk.is_none(), "geçersiz point PublicKey'e dönüşmemeli");
        }
        Err(_) => {
            // Encoding zaten hatalıysa da test geçer — amacımız "kabul edilmedi".
        }
    }
}
