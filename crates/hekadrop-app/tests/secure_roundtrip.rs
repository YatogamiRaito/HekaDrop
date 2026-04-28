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

//! Secure message (AES-256-CBC + HMAC-SHA256 + sequence counter) uyumluluğu.
//!
//! HekaDrop `src/secure.rs` davranışının bağımsız bir protokol-uyumlu implementasyonu
//! üzerinden roundtrip, replay, HMAC tampering ve out-of-order senaryoları doğrulanır.

mod common;

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use common::hmac_sha256;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    Aes256CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(pt)
}

fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ct: &[u8],
) -> Result<Vec<u8>, cipher::block_padding::UnpadError> {
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ct)
}

/// Ciphertext + IV + HMAC tag'i "sahte secure message" olarak tek vector'e serialize.
/// Production `SecureMessage` protobuf yapısından farklı (kısa test shim'i), ama
/// aynı *kriptografik kontratı* test eder: tek byte değişirse HMAC patlar.
fn encode_sm(ct: &[u8], iv: &[u8; 16], tag: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + ct.len() + 32);
    out.extend_from_slice(iv);
    out.extend_from_slice(ct);
    out.extend_from_slice(tag);
    out
}

fn decode_sm(buf: &[u8]) -> Option<(Vec<u8>, [u8; 16], [u8; 32])> {
    if buf.len() < 16 + 32 {
        return None;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&buf[..16]);
    let tag_start = buf.len() - 32;
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&buf[tag_start..]);
    let ct = buf[16..tag_start].to_vec();
    Some((ct, iv, tag))
}

/// Secure context — HekaDrop `SecureCtx` karşılığı. Sequence counter monoton artar;
/// eksik ya da geri giden sequence reddedilir.
struct SecureCtx {
    encrypt_key: [u8; 32],
    decrypt_key: [u8; 32],
    send_hmac_key: [u8; 32],
    recv_hmac_key: [u8; 32],
    tx_seq: i32,
    rx_seq: i32,
}

impl SecureCtx {
    fn new(enc: [u8; 32], dec: [u8; 32], send_mac: [u8; 32], recv_mac: [u8; 32]) -> Self {
        Self {
            encrypt_key: enc,
            decrypt_key: dec,
            send_hmac_key: send_mac,
            recv_hmac_key: recv_mac,
            tx_seq: 0,
            rx_seq: 0,
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.tx_seq += 1;
        // D2D mesaj: `seq (big-endian 4-byte) || plaintext` — gerçek protobuf
        // DeviceToDeviceMessage yerine seq'i ilk 4 bayta gömüyoruz. Amaç kripto
        // kontratını test etmek, protobuf codec'ini değil (bu ayrı frame_codec.rs'de).
        let mut d2d = Vec::with_capacity(4 + plaintext.len());
        d2d.extend_from_slice(&self.tx_seq.to_be_bytes());
        d2d.extend_from_slice(plaintext);

        // Deterministik test için IV'yi seq'ten türet (production'da rastgele olmalı)
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&self.tx_seq.to_be_bytes());
        let ct = aes256_cbc_encrypt(&self.encrypt_key, &iv, &d2d);

        // HMAC IV || ciphertext üzerine
        let mut hb = Vec::new();
        hb.extend_from_slice(&iv);
        hb.extend_from_slice(&ct);
        let tag = hmac_sha256(&self.send_hmac_key, &hb);

        encode_sm(&ct, &iv, &tag)
    }

    fn decrypt(&mut self, buf: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (ct, iv, tag) = decode_sm(buf).ok_or("frame too short")?;
        let mut hb = Vec::new();
        hb.extend_from_slice(&iv);
        hb.extend_from_slice(&ct);
        let expected = hmac_sha256(&self.recv_hmac_key, &hb);
        // Constant-time karşılaştırma production'da subtle; test için eq yeterli.
        if expected != tag {
            return Err("HMAC mismatch");
        }
        let d2d = aes256_cbc_decrypt(&self.decrypt_key, &iv, &ct).map_err(|_| "AES unpad")?;
        if d2d.len() < 4 {
            return Err("D2D too short");
        }
        let mut seq_be = [0u8; 4];
        seq_be.copy_from_slice(&d2d[..4]);
        let seq = i32::from_be_bytes(seq_be);
        let expected_seq = self.rx_seq + 1;
        if seq != expected_seq {
            // Sequence uyuşmaması → state bozulmamalı (retry desteklemek için)
            return Err("sequence mismatch");
        }
        self.rx_seq = expected_seq;
        Ok(d2d[4..].to_vec())
    }
}

fn make_pair() -> (SecureCtx, SecureCtx) {
    let enc_a = [11u8; 32];
    let sig_a = [22u8; 32];
    let enc_b = [33u8; 32];
    let sig_b = [44u8; 32];
    // A.encrypt_key == B.decrypt_key, A.send_hmac == B.recv_hmac
    let a = SecureCtx::new(enc_a, enc_b, sig_a, sig_b);
    let b = SecureCtx::new(enc_b, enc_a, sig_b, sig_a);
    (a, b)
}

#[test]
fn aes_cbc_roundtrip_basit() {
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let pt = b"quick brown fox 1234567890!";
    let ct = aes256_cbc_encrypt(&key, &iv, pt);
    assert_ne!(&ct[..], pt, "ciphertext plaintext ile aynı olmamalı");
    let dec = aes256_cbc_decrypt(&key, &iv, &ct).expect("unpad ok");
    assert_eq!(dec, pt);
}

#[test]
fn aes_cbc_pkcs7_bos_plaintext() {
    // PKCS7 boş plaintext için bir tam blok padding üretir (16 bayt).
    let key = [5u8; 32];
    let iv = [6u8; 16];
    let ct = aes256_cbc_encrypt(&key, &iv, b"");
    assert_eq!(ct.len(), 16);
    let dec = aes256_cbc_decrypt(&key, &iv, &ct).expect("unpad ok");
    assert_eq!(dec.len(), 0);
}

#[test]
fn hmac_authentication_tek_bit_fark_yakalanir() {
    let key = [7u8; 32];
    let msg = b"kritik mesaj";
    let tag = hmac_sha256(&key, msg);
    assert_eq!(tag.len(), 32);

    // Tek bayt bozulsa tag tamamen değişir
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0x01;
    let tag2 = hmac_sha256(&key, &tampered);
    assert_ne!(tag, tag2);
}

#[test]
fn secure_roundtrip_ab_a_dan_b_ye() {
    let (mut a, mut b) = make_pair();
    let msg = b"hello secure channel";
    let enc = a.encrypt(msg);
    let dec = b.decrypt(&enc).expect("decrypt ok");
    assert_eq!(dec, msg);
    assert_eq!(a.tx_seq, 1);
    assert_eq!(b.rx_seq, 1);
}

#[test]
fn sequence_counter_monoton_artar() {
    let (mut a, mut b) = make_pair();
    for i in 1..=5 {
        let msg = format!("msg #{i}");
        let enc = a.encrypt(msg.as_bytes());
        let dec = b.decrypt(&enc).expect("decrypt");
        assert_eq!(dec, msg.as_bytes());
    }
    assert_eq!(a.tx_seq, 5);
    assert_eq!(b.rx_seq, 5);
}

/// Replay attack: aynı ciphertext ikinci kez gönderilirse reject.
/// HekaDrop `SecureCtx::decrypt` fonksiyonu `client_seq`'i advance ettikten sonra
/// aynı frame'i yine almaya çalışırsak sequence "beklenen" ile uyuşmaz.
#[test]
fn replay_saldirisi_ayni_seq_ikinci_kez_rejected() {
    let (mut a, mut b) = make_pair();
    let enc = a.encrypt(b"first message");
    let dec = b.decrypt(&enc).expect("ilk kabul edilmeli");
    assert_eq!(dec, b"first message");

    // Aynı frame'i bir daha gönder
    let replay = b.decrypt(&enc);
    assert!(replay.is_err(), "replay reddedilmeli");
    // Hata türü sequence ile ilgili olmalı
    let err = replay.unwrap_err();
    assert!(err.contains("sequence"), "sequence error: got '{err}'");
}

/// Out-of-order: seq atlanırsa reject. Göndericiden 3 mesaj geliyor ama
/// ortadaki drop edilmiş, 1→3 sırayla geliyor. 3. olan reddedilmeli.
#[test]
fn out_of_order_seq_atlanirsa_rejected() {
    let (mut a, mut b) = make_pair();
    let e1 = a.encrypt(b"one");
    let _e2 = a.encrypt(b"two");
    let e3 = a.encrypt(b"three");

    b.decrypt(&e1).expect("1. kabul");
    // Doğrudan 3.'yi dene — 2 bekleniyordu, 3 geldi
    let r = b.decrypt(&e3);
    assert!(r.is_err(), "ooo reddedilmeli");
}

/// Out-of-order başarısızlık sonrası state bozulmamalı — aynı "eksik" seq'i
/// hâlâ kabul edebilmeliyiz (retry desteği).
#[test]
fn basarisiz_decrypt_sonrasi_state_bozulmaz() {
    let (mut a, mut b) = make_pair();
    let e1 = a.encrypt(b"one");
    let e2 = a.encrypt(b"two");

    // Önce 2. mesajı dene — seq uyumsuz, reject, ama rx_seq advance etmemeli
    let r = b.decrypt(&e2);
    assert!(r.is_err());
    assert_eq!(b.rx_seq, 0, "başarısız decrypt state'i bozmamalı");

    // Sonra 1.'yi dene — hâlâ kabul edilmeli
    let d = b.decrypt(&e1).expect("1. kabul edilmeli");
    assert_eq!(d, b"one");
    assert_eq!(b.rx_seq, 1);
}

/// HMAC tampering: cipher text'in son byte'ı değiştirilirse HMAC patlamalı.
/// Bu testin var oluş sebebi: HekaDrop secure layer subtle::ConstantTimeEq
/// kullanıyor, bu doğrulanırken constant-time olsa bile yanlış tag *reddedilmeli*.
#[test]
fn tampered_hmac_reddedilir() {
    let (mut a, mut b) = make_pair();
    let mut enc = a.encrypt(b"secret payload");
    // Son 32 byte HMAC — ortasındaki bir biti flip et
    let idx = enc.len() - 16;
    enc[idx] ^= 0xFF;
    let r = b.decrypt(&enc);
    assert!(r.is_err(), "HMAC bozulmuşken reddedilmeli");
    let e = r.unwrap_err();
    assert!(e.contains("HMAC"), "HMAC error beklenir: '{e}'");
}

/// Ciphertext tampering (HMAC'i yeniden hesaplamadan ciphertext'i değiştir):
/// HMAC IV||ciphertext üzerine bindiği için bu da HMAC ile yakalanır.
#[test]
fn tampered_ciphertext_hmac_ile_yakalanir() {
    let (mut a, mut b) = make_pair();
    let mut enc = a.encrypt(b"yet another secret");
    // Orta kısım — ciphertext bölgesi (IV sonrası, HMAC öncesi)
    let mid = 16 + (enc.len() - 16 - 32) / 2;
    enc[mid] ^= 0x01;
    let r = b.decrypt(&enc);
    assert!(r.is_err());
}

/// 2 yönlü (A↔B) çift yönlü trafik. A'nın send_seq'i ile B'nin send_seq'i
/// bağımsız — her yön kendi sayacını yönetmeli.
#[test]
fn cift_yonlu_trafik_seq_bagimsiz() {
    let (mut a, mut b) = make_pair();
    let msg_ab = b"A-to-B #1";
    let msg_ba = b"B-to-A #1";
    let enc_a_to_b = a.encrypt(msg_ab);
    let enc_b_to_a = b.encrypt(msg_ba);

    let dec_at_b = b.decrypt(&enc_a_to_b).expect("A->B ok");
    let dec_at_a = a.decrypt(&enc_b_to_a).expect("B->A ok");
    assert_eq!(dec_at_b, msg_ab);
    assert_eq!(dec_at_a, msg_ba);

    // Her iki taraf da kendi sıra numaralarını takip etti
    assert_eq!(a.tx_seq, 1);
    assert_eq!(a.rx_seq, 1);
    assert_eq!(b.tx_seq, 1);
    assert_eq!(b.rx_seq, 1);
}

/// Büyük payload (100 KB) — AES-CBC ciphertext bloklar halinde çözülmeli.
#[test]
fn buyuk_payload_100kb_roundtrip() {
    let (mut a, mut b) = make_pair();
    let big: Vec<u8> = (0..100 * 1024).map(|i| (i & 0xFF) as u8).collect();
    let enc = a.encrypt(&big);
    let dec = b.decrypt(&enc).expect("100 KB ok");
    assert_eq!(dec.len(), big.len());
    assert_eq!(dec, big);
}
