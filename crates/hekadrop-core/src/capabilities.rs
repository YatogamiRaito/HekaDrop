//! `HekaDrop` protocol extension capability negotiation (RFC-0003 §3.2).
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
    ///
    /// **Yalnızca implementasyonu hazır feature'lar advertise edilir** (PR #103
    /// Copilot review): peer'a bir feature'ı reklam etmek "biz bu
    /// extension frame'lerini doğru handle edebiliriz" sözleşmesidir.
    ///
    /// Tarihçe (RFC-0004 `RESUME_V1`):
    /// - PR-F'de açıldı, **PR #136 Gemini high yorumu sonrası geri kapatıldı**
    ///   (receiver `truncate(true)` → veri kaybı).
    /// - **PR-G ile geri açıldı:** `payload.rs::ingest_file` artık resume
    ///   aktifken `truncate(false)` + `seek(received_bytes)` ile mevcut
    ///   `.part`'a devam eder; hasher önceki byte'larla feed edilir (final
    ///   SHA-256 chain tutarlı kalır); `connection.rs::resolve_resume_path`
    ///   Introduction handler'ında fresh placeholder yerine `meta.dest_path`'i
    ///   register eder.
    ///
    /// Tarihçe (RFC-0005 `FOLDER_STREAM_V1`):
    /// - PR-A → PR-E ile primitives + sender enumerate + receiver extract +
    ///   chunk-HMAC/resume entegrasyonu tamamlandı.
    /// - **PR-F'de aktive edildi**: `ALL_SUPPORTED` bayrağa eklendi; UI
    ///   accept dialog folder summary + completion notification "Klasörü Aç"
    ///   aksiyonu wire'landı; `FOLDER_BUNDLE_MIME` Introduction'da
    ///   bulunduğunda extract pipeline (`crate::folder::extract`) atomic-reject
    ///   garantisiyle devreye girer.
    pub const ALL_SUPPORTED: u64 = CHUNK_HMAC_V1 | RESUME_V1 | FOLDER_STREAM_V1;

    /// Bu build için reserved (henüz hiçbir RFC'nin sahip olmadığı) bit'ler.
    /// Test'lerde forward-compat akışını doğrulamak için kullanılır.
    ///
    /// PR-F (RFC-0005) sonrası `ALL_SUPPORTED = CHUNK_HMAC_V1 | RESUME_V1 |
    /// FOLDER_STREAM_V1`; geri kalan tüm üst bit'ler henüz herhangi bir RFC'ye
    /// atanmamış reserved alandır. Peer'ın "ben bu future bit'i destekliyorum"
    /// demesinin AND ile düşmesi forward-compat semantiğini gösterir.
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
    /// Bitmask — yalnız `FeatureFlag` üyelerinin set edilmiş bitleri.
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

/// `HekaDropFrame { resume_hint = ... }` envelope'unu inşa et.
///
/// RFC-0004 §3.2 + capabilities.md §3.1 slot 12. Receiver `.meta` lookup
/// sonrası eşleşen partial bulduğunda emit eder; sender consume ederek
/// `[0..offset]`'i atlar (PR-D).
#[must_use]
pub fn build_resume_hint_frame(hint: hekadrop_proto::hekadrop_ext::ResumeHint) -> HekaDropFrame {
    use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
    HekaDropFrame {
        version: ENVELOPE_VERSION,
        payload: Some(Payload::ResumeHint(hint)),
    }
}

/// `HekaDropFrame { resume_reject = ... }` envelope'unu inşa et.
///
/// RFC-0004 §3.2 + §6 + capabilities.md §3.1 slot 13. Sender, peer'dan
/// gelen `ResumeHint` spec §5 invariant'larından birini ihlal ettiğinde
/// emit eder; receiver bu frame'i alınca §6 reason matrix'ine göre
/// `.part`/`.meta` cleanup yapar (PR-E).
#[must_use]
pub fn build_resume_reject_frame(
    reject: hekadrop_proto::hekadrop_ext::ResumeReject,
) -> HekaDropFrame {
    use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
    HekaDropFrame {
        version: ENVELOPE_VERSION,
        payload: Some(Payload::ResumeReject(reject)),
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
    fn resume_hint_protobuf_roundtrip() {
        // RFC-0004 §3.2 + docs/protocol/resume.md §3 — 6 field spec.
        // Wire'da henüz emit edilmiyor; bu test schema'nın spec'e
        // hizalı encode/decode ettiğini sabitler (PR-B'de emit/parse
        // implementasyonu eklenince regression detector görevi).
        use hekadrop_proto::hekadrop_ext::ResumeHint;

        let original = ResumeHint {
            session_id: 0x0123_4567_89AB_CDEF_i64,
            payload_id: 42,
            offset: 1_048_576,
            partial_hash: vec![0xAA; 32].into(),
            capabilities_version: 1,
            last_chunk_tag: vec![0xBB; 32].into(),
        };
        let bytes = original.encode_to_vec();
        let decoded = ResumeHint::decode(&*bytes).expect("valid wire encoding");
        assert_eq!(decoded.session_id, original.session_id);
        assert_eq!(decoded.payload_id, original.payload_id);
        assert_eq!(decoded.offset, original.offset);
        assert_eq!(decoded.partial_hash, original.partial_hash);
        assert_eq!(decoded.capabilities_version, original.capabilities_version);
        assert_eq!(decoded.last_chunk_tag, original.last_chunk_tag);
    }

    #[test]
    fn resume_reject_all_reasons_roundtrip() {
        // RFC-0004 §3.2 + docs/protocol/resume.md §3 — 7 reason variant.
        // Tüm enum değerlerinin encode + decode round-trip'i korunduğunu
        // sabitler (proto3 unknown variant fallback hata kaynağı olabilir).
        use hekadrop_proto::hekadrop_ext::resume_reject::Reason;
        use hekadrop_proto::hekadrop_ext::ResumeReject;

        let reasons = [
            Reason::Unspecified,
            Reason::HashMismatch,
            Reason::InvalidOffset,
            Reason::VersionMismatch,
            Reason::PayloadUnknown,
            Reason::SessionMismatch,
            Reason::InternalError,
        ];
        for r in reasons {
            let original = ResumeReject {
                payload_id: 7,
                reason: i32::from(r),
            };
            let bytes = original.encode_to_vec();
            let decoded = ResumeReject::decode(&*bytes).expect("valid wire encoding");
            assert_eq!(decoded.payload_id, original.payload_id);
            assert_eq!(decoded.reason, original.reason);
            assert_eq!(Reason::try_from(decoded.reason).expect("known variant"), r);
        }
    }

    #[test]
    fn resume_hint_envelope_oneof_slot_12() {
        // HekaDropFrame.payload oneof slot 12 = resume_hint (capabilities.md
        // §3.1 slot policy). Dispatch'in doğru variant'ı seçtiğini sabitler.
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        use hekadrop_proto::hekadrop_ext::ResumeHint;

        let hint = ResumeHint {
            session_id: 1,
            payload_id: 2,
            offset: 3,
            partial_hash: vec![0; 32].into(),
            capabilities_version: 1,
            last_chunk_tag: vec![0; 32].into(),
        };
        let frame = HekaDropFrame {
            version: ENVELOPE_VERSION,
            payload: Some(Payload::ResumeHint(hint.clone())),
        };
        let bytes = frame.encode_to_vec();
        let decoded = HekaDropFrame::decode(&*bytes).expect("valid wire encoding");
        match decoded.payload {
            Some(Payload::ResumeHint(h)) => {
                assert_eq!(h.session_id, hint.session_id);
                assert_eq!(h.payload_id, hint.payload_id);
                assert_eq!(h.offset, hint.offset);
            }
            other => panic!("beklenen oneof slot 12 (resume_hint), bulundu: {other:?}"),
        }
    }

    #[test]
    fn resume_reject_envelope_oneof_slot_13() {
        // HekaDropFrame.payload oneof slot 13 = resume_reject (capabilities.md
        // §3.1 slot policy). Dispatch'in doğru variant'ı seçtiğini sabitler.
        use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload;
        use hekadrop_proto::hekadrop_ext::resume_reject::Reason;
        use hekadrop_proto::hekadrop_ext::ResumeReject;

        let reject = ResumeReject {
            payload_id: 99,
            reason: i32::from(Reason::SessionMismatch),
        };
        let frame = HekaDropFrame {
            version: ENVELOPE_VERSION,
            payload: Some(Payload::ResumeReject(reject)),
        };
        let bytes = frame.encode_to_vec();
        let decoded = HekaDropFrame::decode(&*bytes).expect("valid wire encoding");
        match decoded.payload {
            Some(Payload::ResumeReject(r)) => {
                assert_eq!(r.payload_id, reject.payload_id);
                assert_eq!(r.reason, reject.reason);
            }
            other => panic!("beklenen oneof slot 13 (resume_reject), bulundu: {other:?}"),
        }
    }

    #[test]
    fn all_supported_only_has_implemented_features() {
        // PR #103 review (Copilot): ALL_SUPPORTED yalnızca implementasyonu
        // hazır feature'ları içerir. RFC-0004 (RESUME_V1) PR-G ile geri
        // açıldı (receiver append/seek + hasher feed entegre). **RFC-0005
        // (FOLDER_STREAM_V1) PR-F ile aktive edildi**: PR-A → PR-E ile
        // primitives + sender + receiver + chunk-HMAC/resume entegrasyonu
        // tamamlandı, PR-F UI dialog + completion notification + capability
        // gate açtı.
        assert_eq!(
            features::ALL_SUPPORTED,
            features::CHUNK_HMAC_V1 | features::RESUME_V1 | features::FOLDER_STREAM_V1
        );
        assert_ne!(features::ALL_SUPPORTED & features::CHUNK_HMAC_V1, 0);
        assert_ne!(features::ALL_SUPPORTED & features::RESUME_V1, 0);
        assert_ne!(features::ALL_SUPPORTED & features::FOLDER_STREAM_V1, 0);
    }
}
