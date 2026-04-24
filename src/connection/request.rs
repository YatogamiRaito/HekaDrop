//! Plain `ConnectionRequest` okuması + endpoint kimliği çözümü ve rate-limit kontrolü.
//!
//! Bu modül handshake'in "pre-UKEY2" fazını tutar: peer'ın uzak cihaz adı + endpoint_id
//! çıkarılır, trust listesine göre rate-limit uygulanır (trusted cihazlar muaftır).

use crate::error::HekaError;
use crate::frame;
use crate::location::nearby::connections::OfflineFrame;
use crate::state;
use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Plain `ConnectionRequest` frame'inden çıkarılan özet.
pub(crate) struct PeerIntro {
    pub remote_name: String,
    pub remote_id: String,
}

/// 1. adım: `ConnectionRequest` okunur, peer adı + endpoint id parse edilir.
///
/// Ayrıca rate-limit kontrolü uygulanır. Trusted cihazlar (legacy `(name, id)`
/// eşleşmesiyle) rate-limit'ten muaftır — gerçek trust kararı ileride
/// `PairedKeyEncryption`/`Introduction` adımlarında hash-first yapılır.
pub(crate) async fn read_connection_request(
    socket: &mut TcpStream,
    peer: SocketAddr,
) -> Result<PeerIntro> {
    // 1) plain ConnectionRequest
    // SECURITY: Handshake fazındaki tüm frame okumaları slow-loris DoS'a karşı
    // 30 sn timeout ile sarmalanır; aksi halde saldırgan TCP bağlantı açıp
    // veri göndermeden tokio task'ını sonsuza kadar tutabilir.
    let req = frame::read_frame_timeout(socket, frame::HANDSHAKE_READ_TIMEOUT)
        .await
        .context("ConnectionRequest okunamadı")?;
    let offline = OfflineFrame::decode(req.as_ref()).context("OfflineFrame decode")?;
    let v1 = offline.v1.ok_or_else(|| anyhow!("v1 yok"))?;
    let cr = v1
        .connection_request
        .ok_or_else(|| anyhow!("connection_request yok"))?;
    let endpoint_info = cr
        .endpoint_info
        .clone()
        .ok_or_else(|| anyhow!("endpoint_info yok"))?;
    // endpoint_id: peer'ın kalıcı tanıtıcısı (Bug #32). Eksikse boş kabul;
    // is_trusted() boş id'yi legacy kayıt kabul edeceğinden güvenli.
    let remote_id = cr.endpoint_id.clone().unwrap_or_default();
    let remote_name = parse_remote_name(&endpoint_info).unwrap_or_else(|| "bilinmeyen".into());
    info!(
        "[{}] uzak cihaz: {} (endpoint_id: {})",
        peer,
        remote_name,
        if remote_id.is_empty() {
            "<yok>"
        } else {
            remote_id.as_str()
        }
    );

    // Rate limiting — trusted cihazlar BU KONTROLDEN MUAFTIR (memory kuralı).
    //
    // NOT (Issue #17): Bu noktada `PairedKeyEncryption` henüz gelmedi, peer
    // hash yok → legacy `(name, id)` lookup kullanılıyor. Asıl trust kararı
    // (Introduction) ileride hash-first yapılacağından, rate-limit muafiyeti
    // false-positive ile eşit: saldırgan (name, id)'yi spoof ederse rate
    // limit'ten geçer ama dosya kabulü için dialog gösterilir. Bu, tasarım
    // 017 §5.2'de kabul edilen davranış — legacy uyum window'u kapanana
    // kadar hash-first rate limit eklemek sürdürülebilir değil (her oturumda
    // UKEY2 tamamlanana kadar beklenmeli).
    let trusted_early = state::get()
        .settings
        .read()
        .is_trusted_legacy(&remote_name, &remote_id);
    if !trusted_early {
        let st = state::get();
        if st.rate_limiter.check_and_record(peer.ip()) {
            warn!(
                "[{}] rate limit aşıldı (60 sn pencerede >10 bağlantı), reddediliyor",
                peer
            );
            return Err(HekaError::RateLimited(peer.ip().to_string()).into());
        }
    } else {
        info!("[{}] trusted cihaz — rate limit uygulanmadı", peer);
    }

    Ok(PeerIntro {
        remote_name,
        remote_id,
    })
}

pub(crate) fn parse_remote_name(endpoint_info: &[u8]) -> Option<String> {
    if endpoint_info.len() < 18 {
        return None;
    }
    let name_len = endpoint_info[17] as usize;
    if endpoint_info.len() < 18 + name_len {
        return None;
    }
    String::from_utf8(endpoint_info[18..18 + name_len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_name_reddeder_kisa_buffer() {
        assert!(parse_remote_name(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_remote_name_reddeder_yanlis_uzunluk() {
        // 17. bayt "uzunluk=10" der ama buffer'da o kadar bayt yok.
        let mut buf = vec![0u8; 18];
        buf[17] = 10;
        assert!(parse_remote_name(&buf).is_none());
    }

    #[test]
    fn parse_remote_name_cozer_gecerli_utf8() {
        let name = "Pixel 7";
        let mut buf = vec![0u8; 18];
        buf[17] = name.len() as u8;
        buf.extend_from_slice(name.as_bytes());
        assert_eq!(parse_remote_name(&buf).as_deref(), Some(name));
    }
}
