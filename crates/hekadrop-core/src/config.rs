use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};

const NEARBY_SHARING_MARKER: &[u8] = b"NearbySharing";

/// `_<hex>._tcp.local.` — Quick Share mDNS servis tipi.
pub fn service_type() -> String {
    let hash = Sha256::digest(NEARBY_SHARING_MARKER);
    format!("_{}._tcp.local.", hex::encode_upper(&hash[..6]))
}

// `device_name()` Adım 3 öncesi `crate::platform::device_name()` çağıran bir
// shim'di — `platform` app'a ait olduğu için core'a sığmadı. Tek call site
// (`settings::resolved_device_name`) artık platform helper'ı doğrudan çağırıyor.

pub fn random_endpoint_id() -> [u8; 4] {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    let mut id = [0u8; 4];
    for b in &mut id {
        *b = ALPHABET[rng.gen_range(0..ALPHABET.len())];
    }
    id
}

/// mDNS instance name (10 bayt, URL-safe base64, paddingsiz).
/// Yerleşim: [0x23, id×4, 0xFC, 0x9F, 0x5E, 0x00, 0x00]
pub fn instance_name(endpoint_id: [u8; 4]) -> String {
    let mut bytes = [0u8; 10];
    bytes[0] = 0x23; // PCP
    bytes[1..5].copy_from_slice(&endpoint_id);
    bytes[5..8].copy_from_slice(&[0xFC, 0x9F, 0x5E]);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub const DEVICE_TYPE_COMPUTER: u8 = 3;

/// RFC 6763 §6.1 — bir TXT record içindeki her `<key>=<value>` string'i
/// UTF-8 olarak en fazla 255 bayt olabilir. mDNS yayınımız `n=<base64>`
/// formatında olduğundan key (`n=` = 2 bayt) + base64 değer ≤ 255 olmalı.
const MAX_TXT_STRING_LEN: usize = 255;
const N_KEY_PREFIX_LEN: usize = 2; // "n="

/// `endpoint_info` ham byte yerleşimi sabit prefix'i: bitmap(1) + random(16) +
/// `name_len`(1) = 18 bayt; bunu takiben ad bayt'ları gelir.
const ENDPOINT_INFO_HEADER_LEN: usize = 18;

/// URL-safe base64 (paddingsiz) `n` bayt → `ceil(n * 4 / 3)` karakter üretir.
/// `n=` + base64 ≤ 255 sınırından geriye yürüterek izin verilen ham
/// `endpoint_info` boyutunu hesapla:
///
/// ```text
/// base64_len_max = 255 - 2 = 253
/// raw_max        = floor(base64_len_max * 3 / 4) = 189
/// name_max       = raw_max - 18 = 171
/// ```
///
/// Bu değer hem RFC 6763 §6.1 limit'ini hem de wire `name_len` u8 sınırını
/// (≤ 255) aynı anda sağlar — daha sıkı olan bu limittir.
const MAX_DEVICE_NAME_BYTES: usize = {
    let base64_max = MAX_TXT_STRING_LEN - N_KEY_PREFIX_LEN;
    let raw_max = (base64_max * 3) / 4;
    raw_max - ENDPOINT_INFO_HEADER_LEN
};

/// Ad bayt'larını verilen `max` limitine clamp et — UTF-8 karakter
/// sınırlarını koru (ortadan kırpıp invalid UTF-8 üretme).
fn clamp_to_utf8_boundary(name: &str, max: usize) -> &[u8] {
    if name.len() <= max {
        return name.as_bytes();
    }
    // `floor_char_boundary` stable değil (Rust 1.90); manuel olarak `max`'ten
    // geriye doğru en yakın char boundary'yi bul.
    let mut end = max;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    &name.as_bytes()[..end]
}

/// `EndpointInfo` yapısı — TXT record `n=` değerinin base64'ten öncesi.
/// Yerleşim:
///   `[0]`      bitmap: (sürüm<<5)|(görünürlük<<4)|(`cihaz_tipi`<<1)|rez
///   `[1..17]`  16 bayt rastgele
///   `[17]`     ad uzunluğu (u8)
///   `[18..]`   UTF-8 cihaz adı (max [`MAX_DEVICE_NAME_BYTES`] bayt — bkz.
///              RFC 6763 §6.1 TXT record limit derivasyonu)
pub fn endpoint_info(device_name: &str) -> Vec<u8> {
    let name_bytes = clamp_to_utf8_boundary(device_name, MAX_DEVICE_NAME_BYTES);
    let mut out = Vec::with_capacity(ENDPOINT_INFO_HEADER_LEN + name_bytes.len());
    out.push(DEVICE_TYPE_COMPUTER << 1);

    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 16];
    rng.fill(&mut rnd);
    out.extend_from_slice(&rnd);

    // PROTO: `name_bytes.len()` ≤ MAX_DEVICE_NAME_BYTES (= 171) << 255, yani
    // u8 dönüşümü truncation üretmez.
    #[allow(clippy::cast_possible_truncation)]
    let name_len = name_bytes.len() as u8;
    out.push(name_len);
    out.extend_from_slice(name_bytes);
    out
}

pub fn endpoint_info_b64(device_name: &str) -> String {
    URL_SAFE_NO_PAD.encode(endpoint_info(device_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6763 §6.1 — `n=<base64>` toplam string'i ≤ 255 bayt olmalı.
    /// Cihaz adı kullanıcı kontrollü olduğu için arbitrary uzunluktaki
    /// input'larda da limit'in tutması gerekir; aksi halde Quick Share /
    /// Android tarafı TXT entry'i drop edebilir.
    #[test]
    fn endpoint_info_b64_rfc6763_txt_record_limit() {
        for &len in &[0usize, 1, 32, 100, 171, 200, 255, 1024, 4096] {
            let name = "A".repeat(len);
            let b64 = endpoint_info_b64(&name);
            let txt_entry_len = "n=".len() + b64.len();
            assert!(
                txt_entry_len <= MAX_TXT_STRING_LEN,
                "input len={len} → n=<{b64_len}> = {txt_entry_len} bayt (255 limit aşıldı)",
                b64_len = b64.len(),
            );
        }
    }

    /// Uzun ad UTF-8 char boundary'sinde clamp edilmeli — yarım byte
    /// sequence ile invalid UTF-8 üretmemeli.
    #[test]
    fn endpoint_info_utf8_boundary_safe_clamp() {
        // Her karakter 4 bayt olan emoji string — 200 karakter = 800 bayt.
        let name = "😀".repeat(200);
        let info = endpoint_info(&name);
        let name_len = info[17] as usize;
        let name_slice = &info[18..18 + name_len];
        assert!(
            std::str::from_utf8(name_slice).is_ok(),
            "clamp UTF-8 char boundary'sinde olmalı"
        );
        assert!(name_len <= MAX_DEVICE_NAME_BYTES);
    }

    /// Limit altındaki ad'lar dokunulmadan geçmeli.
    #[test]
    fn endpoint_info_short_name_passthrough() {
        let info = endpoint_info("MacBook");
        assert_eq!(info[17] as usize, "MacBook".len());
        assert_eq!(&info[18..], b"MacBook");
    }
}
