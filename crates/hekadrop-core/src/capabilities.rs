//! HekaDrop protocol extension capability negotiation (RFC-0003 §3.2).
//!
//! Bu modül [`hekadrop_proto::hekadrop_ext`] altındaki üretilmiş
//! `Capabilities` ve `HekaDropFrame` mesajlarını idiomatic Rust API
//! ile sarar. Wire-byte-exact spec: `docs/protocol/capabilities.md`.
//!
//! İki uç da `PairedKeyEncryption` sonrası kendi feature set'ini
//! gönderir; aktif feature `my & peer` ile hesaplanır. 2 sn timeout
//! → legacy mode (`active = 0`).
//!
//! Magic prefix dispatcher [`crate::frame`]'dedir. Bu modül yalnızca
//! capability set semantiği ve protobuf encode/decode wrapper'ı sağlar.

use hekadrop_proto::hekadrop_ext::{Capabilities, HekaDropFrame};

/// `Capabilities.features` bit konumları.
///
/// Bit'ler stable kontrat — major version bump olmadan yer değiştirmez.
/// Yeni RFC bit eklerken numerical olarak en küçük serbest pozisyonu alır
/// ve `ALL_SUPPORTED`'ı günceller.
pub mod features {
    /// RFC-0003 — per-chunk HMAC-SHA256 integrity tag.
    pub const CHUNK_HMAC_V1: u64 = 0x0000_0001;

    /// RFC-0004 — transfer resume hint with partial-hash verification.
    pub const RESUME_V1: u64 = 0x0000_0002;

    /// RFC-0005 — folder bundle with HEKABUND iç format.
    pub const FOLDER_STREAM_V1: u64 = 0x0000_0004;

    /// Bu build'in advertise ettiği tüm feature'lar.
    ///
    /// Sender `Capabilities.features` alanına bunu yazar; alıcı uç da
    /// kendi `ALL_SUPPORTED`'ını yollar. Aktif set:
    /// `my.features & peer.features`. Bilinmeyen üst bit'ler doğal olarak
    /// AND sonucundan düşer (forward-compat).
    pub const ALL_SUPPORTED: u64 = CHUNK_HMAC_V1 | RESUME_V1 | FOLDER_STREAM_V1;

    /// Bu build için reserved (henüz hiçbir RFC'nin sahip olmadığı) bit'ler.
    /// Test'lerde forward-compat akışını doğrulamak için kullanılır.
    #[cfg(test)]
    pub const RESERVED_FUTURE: u64 = !ALL_SUPPORTED;
}

/// `Capabilities` mesaj versiyonu — `Capabilities.version` alanına yazılır.
///
/// v0.8.0 = 1. Şema değişirse (ör. yeni alan eklenirse) bump et.
pub const CAPABILITIES_VERSION: u32 = 1;

/// `HekaDropFrame` envelope versiyonu — `HekaDropFrame.version` alanına yazılır.
///
/// v0.8.0 = 1. Envelope yapısı kapsamlı değişirse (ör. yeni reserved
/// slot kullanımı) bump et.
pub const ENVELOPE_VERSION: u32 = 1;

/// Aktif (her iki uçça desteklenen) feature kümesi.
///
/// Construct edildikten sonra immutable; query method'ları O(1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveCapabilities {
    features: u64,
}

impl ActiveCapabilities {
    /// İki tarafın advertise ettiği feature set'lerinden aktif olanı türet.
    ///
    /// Forward-compat: `peer.features` bu build'in tanımadığı üst bit'leri
    /// içerse de AND ile elenir; aktif kümede bilinen bit'ler kalır.
    #[must_use]
    pub const fn negotiate(my: u64, peer: u64) -> Self {
        Self {
            features: my & peer,
        }
    }

    /// Capabilities exchange başarısız olduğunda (timeout, parse error)
    /// fallback değer. Aktif feature'sız = legacy Quick Share davranışı.
    #[must_use]
    pub const fn legacy() -> Self {
        Self { features: 0 }
    }

    /// Belirli bir feature aktif mi.
    #[must_use]
    pub const fn has(&self, feature: u64) -> bool {
        (self.features & feature) == feature
    }

    /// Aktif feature bitmask'ı (debug + log için).
    #[must_use]
    pub const fn raw(&self) -> u64 {
        self.features
    }

    /// Hiç feature aktif değil mi (legacy mode).
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        self.features == 0
    }
}

/// Bu build'in `Capabilities` advertisement'ı — wire'a gönderilecek
/// protobuf mesajı.
#[must_use]
pub fn build_self_capabilities() -> Capabilities {
    Capabilities {
        version: CAPABILITIES_VERSION,
        features: features::ALL_SUPPORTED,
    }
}

/// `HekaDropFrame { capabilities = ... }` envelope'unu inşa et.
#[must_use]
pub fn build_capabilities_frame(caps: Capabilities) -> HekaDropFrame {
    use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
    HekaDropFrame {
        version: ENVELOPE_VERSION,
        payload: Some(Payload::Capabilities(caps)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn legacy_no_features() {
        let active = ActiveCapabilities::legacy();
        assert!(active.is_legacy());
        assert_eq!(active.raw(), 0);
        assert!(!active.has(features::CHUNK_HMAC_V1));
        assert!(!active.has(features::RESUME_V1));
        assert!(!active.has(features::FOLDER_STREAM_V1));
    }

    #[test]
    fn negotiate_intersection() {
        // Sender supports chunk_hmac + resume; receiver supports
        // chunk_hmac + folder. Intersection = chunk_hmac only.
        let active = ActiveCapabilities::negotiate(
            features::CHUNK_HMAC_V1 | features::RESUME_V1,
            features::CHUNK_HMAC_V1 | features::FOLDER_STREAM_V1,
        );
        assert!(active.has(features::CHUNK_HMAC_V1));
        assert!(!active.has(features::RESUME_V1));
        assert!(!active.has(features::FOLDER_STREAM_V1));
        assert!(!active.is_legacy());
    }

    #[test]
    fn forward_compat_unknown_bits_silently_ignored() {
        // Peer ileri bir versiyondan; bilmediğimiz üst bit'leri
        // advertise ediyor. Bizim build'imiz bu bit'leri tanımıyor;
        // intersection sadece bizim de bildiğimiz bit'leri tutmalı.
        let unknown_future_bit: u64 = 0x0000_8000;
        let peer = features::CHUNK_HMAC_V1 | unknown_future_bit;
        let active = ActiveCapabilities::negotiate(features::ALL_SUPPORTED, peer);
        assert!(active.has(features::CHUNK_HMAC_V1));
        // Bilmediğimiz bit AND sonucundan düşmüş — kontrol için ALL_SUPPORTED
        // dışında hiçbir bit aktif olmamalı.
        assert_eq!(active.raw() & features::RESERVED_FUTURE, 0);
    }

    #[test]
    fn build_self_advertises_all_supported() {
        let caps = build_self_capabilities();
        assert_eq!(caps.version, CAPABILITIES_VERSION);
        assert_eq!(caps.features, features::ALL_SUPPORTED);
    }

    #[test]
    fn capabilities_protobuf_roundtrip() {
        let original = build_self_capabilities();
        let bytes = original.encode_to_vec();
        let decoded = Capabilities::decode(&*bytes).expect("valid wire encoding");
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.features, original.features);
    }

    #[test]
    fn envelope_carries_capabilities_oneof() {
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        let caps = build_self_capabilities();
        let frame = build_capabilities_frame(caps);

        assert_eq!(frame.version, ENVELOPE_VERSION);
        match frame.payload {
            Some(Payload::Capabilities(c)) => {
                assert_eq!(c.version, caps.version);
                assert_eq!(c.features, caps.features);
            }
            other => panic!("beklenen oneof slot 10 (capabilities), bulundu: {other:?}"),
        }
    }

    #[test]
    fn envelope_protobuf_roundtrip() {
        let frame = build_capabilities_frame(build_self_capabilities());
        let bytes = frame.encode_to_vec();
        let decoded = HekaDropFrame::decode(&*bytes).expect("valid wire encoding");
        assert_eq!(decoded.version, frame.version);
        // Payload oneof preserved.
        assert!(decoded.payload.is_some());
    }

    #[test]
    fn all_supported_bitmask_matches_individual_bits() {
        // Regression: ALL_SUPPORTED'ın tek tek bit'lerin OR'u olduğunu
        // doğrula; gelecekte yeni bit eklendiğinde bu test güncellenecek.
        let expected = features::CHUNK_HMAC_V1 | features::RESUME_V1 | features::FOLDER_STREAM_V1;
        assert_eq!(features::ALL_SUPPORTED, expected);
    }
}
