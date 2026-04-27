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

pub fn device_name() -> String {
    crate::platform::device_name()
}

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

/// EndpointInfo yapısı — TXT record `n=` değerinin base64'ten öncesi.
/// Yerleşim:
///   `[0]`      bitmap: (sürüm<<5)|(görünürlük<<4)|(cihaz_tipi<<1)|rez
///   `[1..17]`  16 bayt rastgele
///   `[17]`     ad uzunluğu (u8)
///   `[18..]`   UTF-8 cihaz adı
pub fn endpoint_info(device_name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + device_name.len());
    out.push(DEVICE_TYPE_COMPUTER << 1);

    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 16];
    rng.fill(&mut rnd);
    out.extend_from_slice(&rnd);

    let mut name_bytes = device_name.as_bytes();
    if name_bytes.len() > 255 {
        name_bytes = &name_bytes[..255];
    }
    // PROTO: ad uzunluğu wire'da u8 — yukarıda 255'e clamp ediliyor, truncation imkansız.
    #[allow(clippy::cast_possible_truncation)]
    let name_len = name_bytes.len() as u8;
    out.push(name_len);
    out.extend_from_slice(name_bytes);
    out
}

pub fn endpoint_info_b64(device_name: &str) -> String {
    URL_SAFE_NO_PAD.encode(endpoint_info(device_name))
}
