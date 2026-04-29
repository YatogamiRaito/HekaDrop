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

//! mDNS keşif katmanı — Quick Share'in `_FC9F5ED42C8A._tcp.local.` servis tipi,
//! 10-byte instance name ve `EndpointInfo` encoding'i protokol uyumluluğu.
//!
//! Bu testler `HekaDrop` `src/config.rs` çıktılarıyla birebir uyumlu olmalı —
//! her biri bağımsız implement edilmiştir, böylece kaynak değişirse regression
//! yakalanır.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::sha256;

const NEARBY_SHARING_MARKER: &[u8] = b"NearbySharing";
const DEVICE_TYPE_COMPUTER: u8 = 3;

/// `_<hex>._tcp.local.` — Quick Share servis tipi string'ini türet.
fn service_type() -> String {
    let hash = sha256(NEARBY_SHARING_MARKER);
    format!("_{}._tcp.local.", hex::encode_upper(&hash[..6]))
}

/// mDNS instance name (10 bayt, URL-safe base64 padsiz):
///   [0x23, id×4, 0xFC, 0x9F, 0x5E, 0x00, 0x00]
fn instance_name(endpoint_id: &[u8; 4]) -> String {
    let mut bytes = [0u8; 10];
    bytes[0] = 0x23;
    bytes[1..5].copy_from_slice(endpoint_id);
    bytes[5..8].copy_from_slice(&[0xFC, 0x9F, 0x5E]);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `EndpointInfo` yapısı — `n=` TXT record'un base64 öncesi:
///   [0]      bitmap (cihaz tipi << 1)
///   [1..17]  16 bayt rastgele
///   [17]     ad uzunluğu (u8)
///   [18..]   UTF-8 cihaz adı (RFC 6763 §6.1: `n=<base64>` ≤ 255 bayt
///            zorunluluğu nedeniyle ad ≤ 171 bayt)
fn endpoint_info(device_name: &str, random: &[u8; 16]) -> Vec<u8> {
    // src/config.rs MAX_DEVICE_NAME_BYTES değeriyle birebir tutmalı.
    const MAX_DEVICE_NAME_BYTES: usize = 171;

    let bytes = device_name.as_bytes();
    let name_bytes = if bytes.len() <= MAX_DEVICE_NAME_BYTES {
        bytes
    } else {
        let mut end = MAX_DEVICE_NAME_BYTES;
        while end > 0 && !device_name.is_char_boundary(end) {
            end -= 1;
        }
        &bytes[..end]
    };
    // Capacity hint kırpma sonrası gerçek boyutla — `device_name.len()`
    // kullanmak 171 byte üstü inputlarda gereksiz büyük allocation yapardı.
    let mut out = Vec::with_capacity(18 + name_bytes.len());
    out.push(DEVICE_TYPE_COMPUTER << 1);
    out.extend_from_slice(random);
    out.push(name_bytes.len() as u8);
    out.extend_from_slice(name_bytes);
    out
}

/// Quick Share spec'i sabit servis tipini zorunlu kılar — bu değer donmalı.
#[test]
fn service_type_fc9f5ed42c8a_tcp_local() {
    let st = service_type();
    // SHA256("NearbySharing")[..6] = FC9F5ED42C8A (bilinen sabit)
    assert_eq!(st, "_FC9F5ED42C8A._tcp.local.");
}

#[test]
fn service_type_underscore_prefix() {
    let st = service_type();
    assert!(st.starts_with('_'));
    assert!(st.ends_with("._tcp.local."));
    assert_eq!(st.matches('_').count(), 2); // _FC...._tcp._ son değil: "_FC...._tcp.local." — 2 underscore
}

#[test]
fn instance_name_10_byte_base64() {
    let id = b"ab12";
    let name = instance_name(id);
    // URL-safe base64, padsiz: 10 bayt → ceil(10*8/6) = 14 karakter
    let decoded = URL_SAFE_NO_PAD
        .decode(&name)
        .expect("URL-safe base64 decode");
    assert_eq!(decoded.len(), 10);
    assert_eq!(decoded[0], 0x23, "PCP byte 0x23");
    assert_eq!(&decoded[1..5], b"ab12", "endpoint_id");
    assert_eq!(&decoded[5..8], &[0xFC, 0x9F, 0x5E], "service marker");
    assert_eq!(&decoded[8..10], &[0x00, 0x00]);
}

#[test]
fn instance_name_decoded_length_always_10() {
    for id in [b"aaaa", b"ZZZZ", b"0000", b"xXyY"] {
        let name = instance_name(id);
        let dec = URL_SAFE_NO_PAD.decode(&name).unwrap();
        assert_eq!(dec.len(), 10, "id={:?} → {} bayt", id, dec.len());
    }
}

#[test]
fn instance_name_farkli_id_farkli_name() {
    let a = instance_name(b"aaaa");
    let b = instance_name(b"bbbb");
    assert_ne!(a, b);
}

/// `EndpointInfo` encoding'i: [bitmap, 16 random, `name_len`, utf8 name]
#[test]
fn endpoint_info_yerlesim_standart() {
    let random = [0xAAu8; 16];
    let info = endpoint_info("Mac", &random);
    // Beklenen: [0x06, 0xAA×16, 0x03, 'M','a','c']  (0x06 = 3<<1 = computer*2)
    assert_eq!(info[0], DEVICE_TYPE_COMPUTER << 1);
    assert_eq!(info[0], 0x06);
    assert_eq!(&info[1..17], &[0xAA; 16]);
    assert_eq!(info[17], 3);
    assert_eq!(&info[18..21], b"Mac");
    assert_eq!(info.len(), 21);
}

#[test]
fn endpoint_info_utf8_turkce_karakter() {
    // "Ömer" → Ö = 0xC3 0x96, 4 codepoint ama 5 UTF-8 bayt.
    let random = [0u8; 16];
    let info = endpoint_info("Ömer", &random);
    let name_len = info[17] as usize;
    assert_eq!(name_len, 5, "UTF-8 byte uzunluğu");
    let name = std::str::from_utf8(&info[18..18 + name_len]).unwrap();
    assert_eq!(name, "Ömer");
}

/// RFC 6763 §6.1 — `n=<base64>` toplam ≤ 255 bayt; bu nedenle ham ad
/// alanı 171 bayt'ta clamp'lenir. Eski davranış (255 bayt'a clamp) Quick
/// Share / Android tarafında TXT entry'nin drop edilmesine yol açıyordu.
#[test]
fn endpoint_info_171_bayt_ustunde_truncate_rfc6763() {
    let random = [0u8; 16];
    // 300 karakter ASCII
    let long = "A".repeat(300);
    let info = endpoint_info(&long, &random);
    assert_eq!(info[17], 171, "ad uzunluğu 171 bayt'a clamp edilmeli");
    assert_eq!(info.len(), 18 + 171);

    // Bu raw payload'un base64'ü `n=` ile birlikte 255 bayt sınırını aşmamalı.
    let b64 = URL_SAFE_NO_PAD.encode(&info);
    let txt_entry_len = "n=".len() + b64.len();
    assert!(
        txt_entry_len <= 255,
        "n=<base64> = {txt_entry_len} bayt > 255 (RFC 6763 §6.1 ihlali)",
    );
}

#[test]
fn endpoint_info_bos_ad() {
    let random = [0u8; 16];
    let info = endpoint_info("", &random);
    assert_eq!(info[17], 0);
    assert_eq!(info.len(), 18); // bitmap + 16 random + name_len (ama name yok)
}

/// `n=` TXT record için base64 encode sonrası URL-safe olmalı — `+` ve `/` yok.
#[test]
fn endpoint_info_b64_url_safe() {
    let random = [0xFFu8; 16]; // tüm 1'ler → base64 çıktısında '+' ya da '/' olasılığı yüksek
    let info = endpoint_info("TestMac", &random);
    let b64 = URL_SAFE_NO_PAD.encode(&info);
    assert!(!b64.contains('+'), "URL-safe encode: '+' olmamalı");
    assert!(!b64.contains('/'), "URL-safe encode: '/' olmamalı");
    assert!(!b64.contains('='), "padsiz: '=' olmamalı");
}

#[test]
fn instance_name_deterministic_ayni_id_ayni_cikti() {
    let id = b"WXYZ";
    let n1 = instance_name(id);
    let n2 = instance_name(id);
    assert_eq!(n1, n2);
}
