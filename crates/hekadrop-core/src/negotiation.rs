//! Capabilities exchange — runtime helper (RFC-0003 §3.3).
//!
//! [`negotiate_capabilities`] `PairedKeyEncryption` sonrası, herhangi bir
//! `HekaDrop` extension frame'i emit edilmeden önce çağrılır. Send + receive
//! + 2 sn timeout fallback semantiğini tek async fn içine paketler.
//!
//! Wire-byte-exact spec: [`docs/protocol/capabilities.md`] §5.
//!
//! **State machine entegrasyon notu (v0.8):** Bu helper henüz `sender.rs`
//! veya `connection.rs` ana akışına bağlı değildir; eski Quick Share peer'ları
//! `HekaDropFrame`'i decode edemediğinde davranışları bilinmez (büyük olasılık
//! connection drop). Peer-detection logic (`HekaDrop` extension flag'i mDNS
//! TXT'te) eklendikten sonra ayrı bir PR ile sender + receiver akışlarına
//! entegre edilir.

use bytes::Bytes;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::capabilities::{
    build_capabilities_frame, build_self_capabilities, features, ActiveCapabilities,
};
use crate::frame::{self, dispatch_frame_body, wrap_hekadrop_frame, FrameKind};
use crate::secure::SecureCtx;
use hekadrop_proto::hekadrop_ext::{heka_drop_frame::Payload, HekaDropFrame};
use prost::Message;

/// Capabilities exchange için varsayılan timeout — `docs/protocol/capabilities.md`
/// §5.1 spec değeri (2 sn).
pub const DEFAULT_CAPABILITIES_TIMEOUT: Duration = Duration::from_millis(2000);

/// Capabilities exchange sonucu — caller'ın state machine'i için.
///
/// `leftover_plain`: Peer'ın gönderdiği frame `HekaDropFrame` değilse
/// (örn. legacy `OfflineFrame` veya bozuk bytes), decrypt edilmiş plain
/// payload burada caller'a geri verilir — protokol akışından kaybolmasın.
/// Caller bu byte'ları kendi state machine'ine feed edebilir veya skip
/// edip warn loglayabilir. Decrypt veya read başarısız olursa `None`.
#[derive(Debug)]
pub struct NegotiationOutcome {
    pub active: ActiveCapabilities,
    pub leftover_plain: Option<Bytes>,
}

/// `PairedKeyEncryption` sonrası `HekaDrop` extension capabilities exchange'ini
/// gerçekleştir.
///
/// Akış:
/// 1. Bu build'in `Capabilities` frame'ini `SecureCtx::encrypt` ile şifrele
///    ve gönder.
/// 2. Peer'ın frame'ini `timeout` süresinde bekle.
/// 3. Decrypt + magic prefix dispatch + protobuf decode + payload oneof match.
/// 4. `ActiveCapabilities::negotiate(my, peer)` döndür.
///
/// Herhangi bir hata durumunda (timeout, decrypt fail, decode fail, magic
/// mismatch, oneof slot eşleşmesi yok) **silent** olarak
/// [`ActiveCapabilities::legacy`] döner — capabilities exchange başarısız
/// = legacy mode (no extension features). Kullanıcıya hata gösterilmez;
/// transfer normal Quick Share akışıyla devam edebilir.
///
/// **Frame loss önlemi (PR #110 Gemini high yorumu):** Peer frame'i decrypt
/// edilebildi ama `HekaDropFrame` değilse (örn. legacy `OfflineFrame`),
/// plain payload `leftover_plain` field'ında caller'a döndürülür. Aksi
/// halde frame protokol akışından sessizce yutulurdu. Caller'ın leftover
/// byte'larıyla ne yapacağına karar vermesi state machine entegrasyonuna
/// bağlıdır.
///
/// Caller bu helper'ı `PairedKeyResult` swap'tan sonra, Introduction gönderme/
/// alma öncesinde çağırmalıdır (state machine entegrasyonu için bkz. modül
/// dokümantasyonu).
pub async fn negotiate_capabilities(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    timeout: Duration,
) -> NegotiationOutcome {
    let our_features = features::ALL_SUPPORTED;

    // Step 1: Bu build'in capabilities frame'ini gönder.
    let our = build_capabilities_frame(build_self_capabilities());
    let pb = our.encode_to_vec();
    let wrapped = wrap_hekadrop_frame(&pb);
    let Ok(enc) = ctx.encrypt(&wrapped) else {
        return NegotiationOutcome::legacy_no_leftover();
    };
    if frame::write_frame(socket, &enc).await.is_err() {
        return NegotiationOutcome::legacy_no_leftover();
    }

    // Step 2-4: Peer'ın capabilities'ini al + parse + negotiate.
    let Ok(raw) = frame::read_frame_timeout(socket, timeout).await else {
        return NegotiationOutcome::legacy_no_leftover();
    };
    let Ok(plain) = ctx.decrypt(&raw) else {
        return NegotiationOutcome::legacy_no_leftover();
    };
    // Parse'ı kısa-borrow scope'unda yap; başarısızsa leftover olarak
    // plain'i caller'a geri ver (frame loss yok).
    let parsed_caps = parse_capabilities(&plain);
    match parsed_caps {
        Some(features) => NegotiationOutcome {
            active: ActiveCapabilities::negotiate(our_features, features),
            leftover_plain: None,
        },
        None => NegotiationOutcome::legacy_with_leftover(plain),
    }
}

/// Plain decrypted frame'den `HekaDropFrame::Capabilities.features` çıkar.
/// Magic mismatch / decode fail / oneof slot mismatch → `None`.
fn parse_capabilities(plain: &[u8]) -> Option<u64> {
    let FrameKind::HekaDrop { inner } = dispatch_frame_body(plain) else {
        return None;
    };
    let frame = HekaDropFrame::decode(inner).ok()?;
    let Payload::Capabilities(caps) = frame.payload? else {
        return None;
    };
    Some(caps.features)
}

impl NegotiationOutcome {
    fn legacy_no_leftover() -> Self {
        Self {
            active: ActiveCapabilities::legacy(),
            leftover_plain: None,
        }
    }

    fn legacy_with_leftover(plain: Bytes) -> Self {
        Self {
            active: ActiveCapabilities::legacy(),
            leftover_plain: Some(plain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::ENVELOPE_VERSION;
    use crate::ukey2::DerivedKeys;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Quick Share asimetrik key derivation pattern — server'ın encrypt
    /// key'i client'ın decrypt key'i, vice versa. Production'da UKEY2
    /// handshake sonu üretilen `DerivedKeys` bu çapraz yapıya sahip.
    fn matched_secure_ctx_pair() -> (SecureCtx, SecureCtx) {
        let key_a = [0x42u8; 32];
        let key_b = [0x55u8; 32];
        let hmac_a = [0xAAu8; 32];
        let hmac_b = [0xBBu8; 32];

        let server_keys = DerivedKeys {
            decrypt_key: key_a,
            recv_hmac_key: hmac_a,
            encrypt_key: key_b,
            send_hmac_key: hmac_b,
            auth_key: [0u8; 32],
            pin_code: "0000".to_string(),
            next_secret: [0u8; 32],
        };
        let client_keys = DerivedKeys {
            decrypt_key: key_b,
            recv_hmac_key: hmac_b,
            encrypt_key: key_a,
            send_hmac_key: hmac_a,
            auth_key: [0u8; 32],
            pin_code: "0000".to_string(),
            next_secret: [0u8; 32],
        };

        (
            SecureCtx::from_keys(&server_keys),
            SecureCtx::from_keys(&client_keys),
        )
    }

    /// İki `HekaDrop` peer'ı paralel `negotiate_capabilities` çağırırsa ikisi
    /// de `ALL_SUPPORTED` aktif kümeyi döndürmeli (loopback genuine path).
    #[tokio::test]
    async fn loopback_negotiate_all_features_active() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        let server_task = tokio::spawn(async move {
            let (mut server_socket, _) = listener.accept().await.unwrap();
            negotiate_capabilities(
                &mut server_socket,
                &mut server_ctx,
                DEFAULT_CAPABILITIES_TIMEOUT,
            )
            .await
        });

        let mut client_socket = TcpStream::connect(addr).await.unwrap();
        let client_outcome = negotiate_capabilities(
            &mut client_socket,
            &mut client_ctx,
            DEFAULT_CAPABILITIES_TIMEOUT,
        )
        .await;
        let server_outcome = server_task.await.unwrap();
        let client_active = client_outcome.active;
        let server_active = server_outcome.active;

        // Her iki taraf da kendi build'inin desteklediği TÜM feature'ları
        // advertise ediyor → intersection = ALL_SUPPORTED.
        assert_eq!(client_active.raw(), features::ALL_SUPPORTED);
        assert_eq!(server_active.raw(), features::ALL_SUPPORTED);
        assert!(client_active.has(features::CHUNK_HMAC_V1));
        // PR-F (RFC-0005): hem RESUME_V1 hem FOLDER_STREAM_V1 ALL_SUPPORTED'a
        // dahil; loopback'te üç feature da aktif olur.
        assert!(client_active.has(features::RESUME_V1));
        assert!(client_active.has(features::FOLDER_STREAM_V1));
        assert!(!client_active.is_legacy());
        // Genuine HekaDrop path'inde leftover olmamalı.
        assert!(client_outcome.leftover_plain.is_none());
        assert!(server_outcome.leftover_plain.is_none());
    }

    /// Peer hiç yanıt vermezse (eski Quick Share peer veya crash) helper
    /// `timeout` sonrası legacy mode'a düşmeli.
    #[tokio::test]
    async fn peer_silent_falls_back_to_legacy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_server_ctx_unused, mut client_ctx) = matched_secure_ctx_pair();

        // Server: accept + sessizce socket'i tut, hiç write yapma → peer
        // capabilities asla gelmeyecek.
        let server_task = tokio::spawn(async move {
            let (mut server_socket, _) = listener.accept().await.unwrap();
            // Client'ın yolladığı capabilities frame'ini drain et
            // (yoksa write_frame block olabilir TCP buffer dolduğunda).
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                tokio::io::AsyncReadExt::read(&mut server_socket, &mut buf),
            )
            .await;
            // Sonra sessizce bekle.
            tokio::time::sleep(Duration::from_millis(2500)).await;
            let _ = server_socket.shutdown().await;
        });

        let mut client_socket = TcpStream::connect(addr).await.unwrap();
        let outcome = negotiate_capabilities(
            &mut client_socket,
            &mut client_ctx,
            Duration::from_millis(200), // kısa timeout — test hızlandırma
        )
        .await;

        let _ = server_task.await;

        // Peer yanıt vermedi → legacy fallback, leftover yok.
        assert!(outcome.active.is_legacy());
        assert_eq!(outcome.active.raw(), 0);
        assert!(outcome.leftover_plain.is_none());
    }

    /// Peer geçersiz bytes yollarsa (`HekaDrop` magic'siz, decrypt fails veya
    /// protobuf decode fails) helper legacy'ye düşmeli — exception leak yok.
    #[tokio::test]
    async fn peer_garbage_falls_back_to_legacy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_, mut client_ctx) = matched_secure_ctx_pair();

        let server_task = tokio::spawn(async move {
            let (mut server_socket, _) = listener.accept().await.unwrap();
            // Client'ın frame'ini drain et
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                tokio::io::AsyncReadExt::read(&mut server_socket, &mut buf),
            )
            .await;
            // Server: client'ın matched_secure_ctx'i ile decrypt edemeyeceği
            // garbage encrypted frame yolla. SecureCtx mismatch → decrypt
            // fail → legacy.
            let garbage = b"\x00\x00\x00\x10garbage_payload!";
            let _ = server_socket.write_all(garbage).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let mut client_socket = TcpStream::connect(addr).await.unwrap();
        let outcome = negotiate_capabilities(
            &mut client_socket,
            &mut client_ctx,
            Duration::from_millis(500),
        )
        .await;

        let _ = server_task.await;

        // Garbage bytes → decrypt fail → legacy, leftover yok (decrypt
        // başarısız olduğu için plain bytes elde edilemedi).
        assert!(outcome.active.is_legacy());
        assert!(outcome.leftover_plain.is_none());
    }

    /// Peer `extension_supported=true` demiş ama legacy `OfflineFrame`
    /// yolluyorsa (kötü niyetli/bozuk peer): outcome legacy döner ama
    /// plain bytes `leftover_plain` ile caller'a geri verilir — frame
    /// loss yok (PR #110 Gemini high yorumu fix).
    #[tokio::test]
    async fn peer_offline_frame_returns_leftover() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        let server_task = tokio::spawn(async move {
            let (mut server_socket, _) = listener.accept().await.unwrap();
            // Drain client'ın HekaDrop capabilities frame'ini.
            let _ = frame::read_frame_timeout(&mut server_socket, Duration::from_millis(500)).await;
            // HekaDrop magic'i OLMAYAN, decrypt edilebilir bir plain
            // payload yolla (legacy OfflineFrame'i simüle ediyor — pratikte
            // protobuf encode'una gerek yok; magic mismatch dispatch'te
            // FrameKind::Offline döndürecek, plain bytes leftover'a düşecek).
            // PR #115 Gemini medium: `Bytes::from_static` heap allocation
            // önler + dönüş tipi Bytes olarak kalır (assert_eq! tip uyumu).
            let plain_legacy = Bytes::from_static(b"NOT_A_HEKADROP_FRAME_SENTINEL");
            let enc = server_ctx.encrypt(&plain_legacy).unwrap();
            let _ = frame::write_frame(&mut server_socket, &enc).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            plain_legacy
        });

        let mut client_socket = TcpStream::connect(addr).await.unwrap();
        let outcome = negotiate_capabilities(
            &mut client_socket,
            &mut client_ctx,
            Duration::from_millis(500),
        )
        .await;

        let expected_plain = server_task.await.unwrap();

        assert!(outcome.active.is_legacy());
        let leftover = outcome
            .leftover_plain
            .expect("legacy OfflineFrame plain bytes leftover'a düşmeli");
        assert_eq!(
            leftover, expected_plain,
            "leftover decrypt edilmiş plain payload aynen döndürülmeli"
        );
    }

    /// Default timeout sabit `2000ms` — `docs/protocol/capabilities.md`
    /// §5.1 spec değerini sabitler (regression guard).
    #[test]
    fn default_timeout_matches_spec() {
        assert_eq!(DEFAULT_CAPABILITIES_TIMEOUT, Duration::from_millis(2000));
    }

    /// Envelope version helper'ın gönderdiği frame'de doğru — protokol
    /// versioning için sabit kontrol.
    #[test]
    fn envelope_version_constant_locked() {
        // Test indirect: frame inşa et, version field'ı kontrol et.
        let our = build_capabilities_frame(build_self_capabilities());
        assert_eq!(our.version, ENVELOPE_VERSION);
    }
}
