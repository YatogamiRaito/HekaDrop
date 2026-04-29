use crate::error::HekaError;
use bytes::{BufMut, Bytes, BytesMut};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Handshake fazında (`ConnectionRequest`, UKEY2) slow-loris saldırılarına karşı
/// frame okuma süresinin üst sınırı. 30 sn gerçek peer için fazlasıyla yeter;
/// bu sürede tek bir frame bile gelmezse saldırgan ya da ağ arızası varsayılır.
pub const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Şifreli loop (`PayloadTransfer` / `KeepAlive`) fazında idle üst sınır.
/// Quick Share peer'ları periyodik `KeepAlive` gönderdiği için 60 sn sessizlik
/// ölü bağlantı olarak kabul edilir; slow-loris tokio task sızıntısı
/// engellenir.
pub const STEADY_READ_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn read_frame(stream: &mut TcpStream) -> Result<Bytes, HekaError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(HekaError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// `read_frame` + deadline. Timeout → `HekaError::ReadTimeout`; böylece
/// çağıran taraf tokio task'ını bitirebilir ve socket kapatılır.
pub async fn read_frame_timeout(
    stream: &mut TcpStream,
    deadline: Duration,
) -> Result<Bytes, HekaError> {
    match tokio::time::timeout(deadline, read_frame(stream)).await {
        Ok(res) => res,
        Err(_) => Err(HekaError::ReadTimeout(deadline)),
    }
}

pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), HekaError> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(HekaError::FrameTooLarge(data.len()));
    }
    let mut out = BytesMut::with_capacity(4 + data.len());
    // PROTO: wire 4-byte big-endian length prefix; üstte MAX_FRAME_SIZE (16 MiB) ≪ u32::MAX, truncation imkansız.
    #[allow(clippy::cast_possible_truncation)]
    let len_u32 = data.len() as u32;
    out.put_u32(len_u32);
    out.put_slice(data);
    stream.write_all(&out).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// HekaDrop extension envelope dispatcher (RFC-0003 §3.2)
// ─────────────────────────────────────────────────────────────────────────────

/// `HekaDropFrame` magic prefix — protokol-DIŞINDA, raw 4-byte big-endian.
///
/// Wire layout: `[ HEKADROP_MAGIC_BE (4 bytes) ][ HekaDropFrame protobuf ]`.
/// Magic protobuf field DEĞİL — `fixed32 field=1` olsaydı tag byte `0x0d`
/// olurdu ve "ilk 4 byte sabit prefix" garantisi yıkılırdı (Gemini PR #85
/// review). Bu nedenle magic strip'i bu seviyede yapılır, sonra
/// `HekaDropFrame::decode` çağrılır.
///
/// Wire-byte-exact spec: `docs/protocol/capabilities.md` §2.
pub const HEKADROP_MAGIC_BE: [u8; 4] = [0xA5, 0xDE, 0xB2, 0x01];

/// `dispatch_frame_body`'nin döndürdüğü ayrım — caller frame'in `HekaDrop`
/// extension mı yoksa upstream Quick Share mi olduğunu bilir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameKind<'a> {
    /// Magic prefix eşleşti; `inner` magic'ten sonraki protobuf bytes'ı.
    /// Caller `HekaDropFrame::decode(inner)` ile parse eder.
    HekaDrop { inner: &'a [u8] },
    /// Magic eşleşmedi; bu klasik Quick Share `OfflineFrame` payload'ı.
    /// Caller `OfflineFrame::decode(body)` ile parse eder.
    Offline { body: &'a [u8] },
}

/// `SecureCtx::decrypt`'ten gelen plaintext frame body'sini sınıflandır.
///
/// 4-byte magic prefix kontrolü O(1) memcmp'tir; protobuf parse maliyeti
/// yoktur. Eski Quick Share peer'ı bizim magic'i içeren bir frame görürse
/// `OfflineFrame::decode` hatası alır ve drop eder — bu zaten capabilities
/// gate aktif değilken `HekaDrop`'un GÖNDERMEMESİ gereken bir frame'dir;
/// dispatcher defense-in-depth.
#[must_use]
pub fn dispatch_frame_body(body: &[u8]) -> FrameKind<'_> {
    if body.len() >= HEKADROP_MAGIC_BE.len() && body[..HEKADROP_MAGIC_BE.len()] == HEKADROP_MAGIC_BE
    {
        FrameKind::HekaDrop {
            inner: &body[HEKADROP_MAGIC_BE.len()..],
        }
    } else {
        FrameKind::Offline { body }
    }
}

/// Bir `HekaDropFrame` protobuf encoding'ini wire formatına çevir
/// (magic prefix + protobuf bytes). `SecureCtx::encrypt`'e besleme öncesi.
#[must_use]
pub fn wrap_hekadrop_frame(protobuf_bytes: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(HEKADROP_MAGIC_BE.len() + protobuf_bytes.len());
    out.put_slice(&HEKADROP_MAGIC_BE);
    out.put_slice(protobuf_bytes);
    out.freeze()
}

#[cfg(test)]
mod dispatcher_tests {
    use super::*;

    #[test]
    fn magic_prefix_constant_matches_spec() {
        // Wire-byte-exact: docs/protocol/capabilities.md §2 sabit `0xA5DEB201`.
        assert_eq!(HEKADROP_MAGIC_BE, [0xA5, 0xDE, 0xB2, 0x01]);
    }

    #[test]
    fn dispatch_offline_when_no_magic() {
        // Klasik Quick Share OfflineFrame'i: ilk byte tipik `0x08` (varint
        // tag=1) gibi bir şey; magic'le başlamaz → Offline.
        let body = [0x08u8, 0x05, 0x10, 0x42];
        match dispatch_frame_body(&body) {
            FrameKind::Offline { body: b } => assert_eq!(b, &body),
            other => panic!("Offline beklendi, alındı: {other:?}"),
        }
    }

    #[test]
    fn dispatch_hekadrop_when_magic_present() {
        // Magic + iki byte fake protobuf payload.
        let inner = [0x08u8, 0x01]; // version=1
        let mut body = Vec::new();
        body.extend_from_slice(&HEKADROP_MAGIC_BE);
        body.extend_from_slice(&inner);

        match dispatch_frame_body(&body) {
            FrameKind::HekaDrop { inner: i } => assert_eq!(i, &inner),
            other => panic!("HekaDrop beklendi, alındı: {other:?}"),
        }
    }

    #[test]
    fn dispatch_offline_when_body_shorter_than_magic() {
        // 3 byte (magic 4 byte) — slice OOB olmadan Offline'a düşmeli.
        let body = [0xA5u8, 0xDE, 0xB2];
        match dispatch_frame_body(&body) {
            FrameKind::Offline { body: b } => assert_eq!(b, &body),
            other => panic!("Offline beklendi (kısa body), alındı: {other:?}"),
        }
    }

    #[test]
    fn dispatch_offline_when_first_three_match_but_fourth_differs() {
        // 0xA5 0xDE 0xB2 0xFF — magic'in 4. byte'ı eşleşmiyor.
        let body = [0xA5u8, 0xDE, 0xB2, 0xFF, 0x08, 0x01];
        match dispatch_frame_body(&body) {
            FrameKind::Offline { body: b } => assert_eq!(b, &body),
            other => panic!("Offline beklendi (4. byte fark), alındı: {other:?}"),
        }
    }

    #[test]
    fn dispatch_empty_body() {
        match dispatch_frame_body(&[]) {
            FrameKind::Offline { body } => assert!(body.is_empty()),
            other => panic!("boş body Offline'a düşmeli, alındı: {other:?}"),
        }
    }

    #[test]
    fn wrap_prepends_magic() {
        let pb = [0x08u8, 0x01, 0x52, 0x04];
        let wrapped = wrap_hekadrop_frame(&pb);
        assert_eq!(&wrapped[..4], &HEKADROP_MAGIC_BE);
        assert_eq!(&wrapped[4..], &pb);
    }

    #[test]
    fn wrap_then_dispatch_roundtrip() {
        // Sender: HekaDropFrame protobuf encode + wrap.
        // Receiver: dispatch → HekaDrop kind, inner bytes orijinal protobuf.
        let pb = [0x08u8, 0x01, 0x52, 0x04, 0x08, 0x01, 0x10, 0x07];
        let wire = wrap_hekadrop_frame(&pb);
        match dispatch_frame_body(&wire) {
            FrameKind::HekaDrop { inner } => assert_eq!(inner, &pb),
            other => panic!("roundtrip kırıldı: {other:?}"),
        }
    }

    #[test]
    fn capabilities_kat_legacy_dispatch() {
        // KAT-CAP-1 (capabilities.md §8): legacy fallback frame (features=0).
        // On-wire: A5 DE B2 01 08 01 52 04 08 01 10 00.
        let kat_legacy = [
            0xA5u8, 0xDE, 0xB2, 0x01, // magic
            0x08, 0x01, // HekaDropFrame.version = 1
            0x52, 0x04, // oneof slot 10 (capabilities), length-delimited 4 bytes
            0x08, 0x01, // Capabilities.version = 1
            0x10, 0x00, // Capabilities.features = 0
        ];
        match dispatch_frame_body(&kat_legacy) {
            FrameKind::HekaDrop { inner } => {
                use crate::capabilities::ActiveCapabilities;
                use hekadrop_proto::hekadrop_ext::{heka_drop_frame::Payload, HekaDropFrame};
                use prost::Message;
                let frame = HekaDropFrame::decode(inner).expect("KAT decode");
                assert_eq!(frame.version, 1);
                match frame.payload {
                    Some(Payload::Capabilities(c)) => {
                        assert_eq!(c.version, 1);
                        assert_eq!(c.features, 0);
                        let active = ActiveCapabilities::negotiate(c.features, c.features);
                        assert!(active.is_legacy());
                    }
                    other => panic!("capabilities slot beklendi: {other:?}"),
                }
            }
            other => panic!("magic eşleşmesi bekleniyor, alındı: {other:?}"),
        }
    }

    #[test]
    fn capabilities_kat_all_features_dispatch() {
        // KAT-CAP-2 (capabilities.md §8): tüm v0.8 features (features=0x07).
        let kat_full = [
            0xA5u8, 0xDE, 0xB2, 0x01, // magic
            0x08, 0x01, // version = 1
            0x52, 0x04, // oneof slot 10, len 4
            0x08, 0x01, // Capabilities.version = 1
            0x10, 0x07, // Capabilities.features = 7
        ];
        match dispatch_frame_body(&kat_full) {
            FrameKind::HekaDrop { inner } => {
                use crate::capabilities::{features, ActiveCapabilities};
                use hekadrop_proto::hekadrop_ext::{heka_drop_frame::Payload, HekaDropFrame};
                use prost::Message;
                let frame = HekaDropFrame::decode(inner).expect("KAT decode");
                if let Some(Payload::Capabilities(c)) = frame.payload {
                    assert_eq!(c.features, 0x07);
                    let active = ActiveCapabilities::negotiate(features::ALL_SUPPORTED, c.features);
                    // PR-F: ALL_SUPPORTED = CHUNK_HMAC_V1 | RESUME_V1 (RFC-0004
                    // implementasyonu tamamlandı). Peer 0x07 (RESUME + FOLDER +
                    // CHUNK) advertise etse de intersection sadece bizim build'imizin
                    // bildiği bit'leri tutar — FOLDER_STREAM_V1 (RFC-0005) hâlâ
                    // implementasyonsuz olduğundan forward-compat ile düşer.
                    assert!(active.has(features::CHUNK_HMAC_V1));
                    assert!(active.has(features::RESUME_V1));
                    assert!(!active.has(features::FOLDER_STREAM_V1));
                } else {
                    panic!("capabilities oneof beklendi");
                }
            }
            other => panic!("magic eşleşmesi bekleniyor: {other:?}"),
        }
    }
}
