//! Quick Share gönderici — Mac → Android yönü.
//!
//! Akış:
//!   1) TCP connect
//!   2) ConnectionRequest (plain, bizim endpoint_info)
//!   3) UKEY2 client handshake → DerivedKeys + PIN
//!   4) Plain ConnectionResponse değişimi (biz → peer, peer → biz)
//!   5) SecureCtx kur — artık tüm trafik şifreli
//!   6) PairedKeyEncryption gönder (biz başlatırız)
//!   7) Peer'den PairedKeyEncryption al → PairedKeyResult gönder
//!   8) Peer'den PairedKeyResult al
//!   9) Introduction gönder (dosya metadata'sı ile)
//!  10) Peer'den Response (Accept/Reject) bekle
//!  11) Accept ise: dosya chunk'larını PayloadTransfer olarak gönder
//!  12) Disconnection

use crate::config;
use crate::connection;
use crate::discovery::DiscoveredDevice;
use crate::frame;
use crate::location::nearby::connections::{
    connection_request_frame::Medium,
    payload_transfer_frame::{
        self as ptf, payload_header::PayloadType, PayloadChunk, PayloadHeader,
    },
    v1_frame, ConnectionRequestFrame, OfflineFrame, PayloadTransferFrame, V1Frame,
};
use crate::payload::{CompletedPayload, PayloadAssembler};
use crate::secure::SecureCtx;
use crate::sharing::nearby::{
    connection_response_frame::Status as ConsentStatus, file_metadata::Type as FileKind,
    frame::Version as ShVersion, v1_frame as sh_v1, FileMetadata, Frame as SharingFrame,
    IntroductionFrame, V1Frame as ShV1Frame,
};
use crate::state::{self, ProgressState};
use crate::ukey2;
use anyhow::{anyhow, bail, Result};
use prost::Message;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Tek chunk'ta gönderilecek maksimum dosya baytı.
/// Quick Share yönergeleri 512 KB civarını öneriyor; 1 MB sınırı zorlar.
const CHUNK_SIZE: usize = 512 * 1024;

pub struct SendRequest {
    pub device: DiscoveredDevice,
    pub files: Vec<std::path::PathBuf>,
}

struct PlannedFile {
    path: std::path::PathBuf,
    name: String,
    size: i64,
    payload_id: i64,
}

pub async fn send(req: SendRequest) -> Result<()> {
    if req.files.is_empty() {
        bail!("en az bir dosya gerekli");
    }

    let mut plans: Vec<PlannedFile> = Vec::with_capacity(req.files.len());
    for path in &req.files {
        if !path.exists() {
            bail!("dosya bulunamadı: {}", path.display());
        }
        let meta = std::fs::metadata(path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dosya")
            .to_string();
        // u64 → i64 cast: meta.len() en fazla u64::MAX olabilir; i64::MAX üstü saçma
        // (8 EB). Güvenli tarafta kalmak için clamp ediyoruz; bu korumada tek bir
        // dosyanın 8 EB'den büyük olması gibi absürt bir senaryoyu elemiş oluruz.
        let raw_size = meta.len();
        if raw_size > i64::MAX as u64 {
            bail!(
                "dosya çok büyük (≥ {} bayt, desteklenmiyor): {}",
                i64::MAX,
                path.display()
            );
        }
        plans.push(PlannedFile {
            path: path.clone(),
            name,
            size: raw_size as i64,
            payload_id: rand::thread_rng().next_u64() as i64,
        });
    }
    // Multi-file toplamda i64 overflow olmaması için checked_add kullan.
    // 60 GB üstü senaryoda bile i64 hâlâ rahat, ama yine de savunmacı yaklaşım.
    let total_bytes: i64 = plans
        .iter()
        .try_fold(0i64, |acc, p| acc.checked_add(p.size))
        .ok_or_else(|| anyhow!("toplam bayt i64 kapasitesini aştı"))?;
    // Bug #30: Boş dosya(lar) → total_bytes == 0 → aşağıda yüzde hesabı 0/0 olur.
    // Boş dosya göndermeyi reddetmek en açık davranış; UI kullanıcıya anlamlı hata gösterir.
    if total_bytes == 0 {
        bail!("boş dosya gönderilemez (toplam 0 bayt)");
    }
    info!(
        "[sender] hedef: {} ({}:{}), {} dosya, toplam {} bayt",
        req.device.name,
        req.device.addr,
        req.device.port,
        plans.len(),
        total_bytes
    );

    let addr = format!("{}:{}", req.device.addr, req.device.port);
    let mut socket = TcpStream::connect(&addr).await?;
    info!("[sender] TCP bağlantı: {} ✓", addr);

    // 2) Plain ConnectionRequest
    let our_name = state::get().settings.read().resolved_device_name();
    let conn_req = build_connection_request(&our_name);
    frame::write_frame(&mut socket, &conn_req.encode_to_vec()).await?;
    info!("[sender] ConnectionRequest gönderildi");

    // 3) UKEY2 client handshake
    let keys = ukey2::client_handshake(&mut socket).await?;
    // SECURITY: PIN clear-text log'a yazılmaz (bkz. connection.rs).
    info!(
        "[sender] ✓ UKEY2 tamam — session fingerprint: {}",
        crate::crypto::session_fingerprint(&keys.auth_key)
    );

    // 4) Plain ConnectionResponse exchange
    let our_resp = connection::build_connection_response_accept();
    frame::write_frame(&mut socket, &our_resp.encode_to_vec()).await?;
    let peer_resp_raw =
        frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT).await?;
    let _peer_resp = OfflineFrame::decode(peer_resp_raw.as_ref())?;
    info!("[sender] ConnectionResponse değişimi tamam");

    // 5) SecureCtx kur
    let mut ctx = SecureCtx::from_keys(&keys);
    let mut assembler = PayloadAssembler::new();

    // 6) PairedKeyEncryption (biz başlatıyoruz)
    connection::send_sharing_frame(
        &mut socket,
        &mut ctx,
        &connection::build_paired_key_encryption(),
    )
    .await?;
    info!("[sender] PairedKeyEncryption gönderildi");

    // 7-11) Loop — peer sharing frame'lerini işle, duruma göre sıradaki adımı tetikle
    let mut introduction_sent = false;
    let mut sent_paired_result = false;
    let peer_label = req.device.name.clone();
    state::clear_cancel();

    loop {
        if state::is_cancelled() {
            info!("[sender] kullanıcı iptal etti");
            let cancel = connection::build_sharing_cancel();
            connection::send_sharing_frame(&mut socket, &mut ctx, &cancel)
                .await
                .ok();
            connection::send_disconnection(&mut socket, &mut ctx)
                .await
                .ok();
            state::clear_cancel();
            state::set_progress(ProgressState::Idle);
            bail!("kullanıcı aktarımı iptal etti");
        }

        let raw = frame::read_frame_timeout(&mut socket, frame::STEADY_READ_TIMEOUT).await?;
        let inner = ctx.decrypt(&raw)?;
        let offline = OfflineFrame::decode(inner.as_ref())?;
        let Some(v1) = offline.v1 else { continue };
        let ftype = v1
            .r#type
            .and_then(|t| v1_frame::FrameType::try_from(t).ok());

        match ftype {
            Some(v1_frame::FrameType::PayloadTransfer) => {
                let pt = v1
                    .payload_transfer
                    .ok_or_else(|| anyhow!("payload_transfer yok"))?;
                let Some(done) = assembler.ingest(&pt)? else {
                    continue;
                };
                let CompletedPayload::Bytes { data, .. } = done else {
                    continue;
                };
                let Ok(sharing) = SharingFrame::decode(&data[..]) else {
                    continue;
                };
                let shv1 = sharing
                    .v1
                    .as_ref()
                    .ok_or_else(|| anyhow!("sharing v1 yok"))?;
                let stype = shv1.r#type.and_then(|t| sh_v1::FrameType::try_from(t).ok());
                match stype {
                    Some(sh_v1::FrameType::PairedKeyEncryption) => {
                        if !sent_paired_result {
                            connection::send_sharing_frame(
                                &mut socket,
                                &mut ctx,
                                &connection::build_paired_key_result(),
                            )
                            .await?;
                            sent_paired_result = true;
                            info!("[sender] PairedKeyResult gönderildi");
                        }
                    }
                    Some(sh_v1::FrameType::PairedKeyResult) => {
                        info!("[sender] peer PairedKeyResult aldı");
                        if !introduction_sent {
                            let intro = build_introduction_multi(&plans);
                            connection::send_sharing_frame(&mut socket, &mut ctx, &intro).await?;
                            introduction_sent = true;
                            info!("[sender] Introduction gönderildi — {} dosya", plans.len());
                        }
                    }
                    Some(sh_v1::FrameType::Response) => {
                        let status = shv1
                            .connection_response
                            .as_ref()
                            .and_then(|r| r.status)
                            .unwrap_or(0);
                        let accepted = status == ConsentStatus::Accept as i32;
                        info!(
                            "[sender] peer Response status={} (accept={})",
                            status, accepted
                        );
                        if !accepted {
                            connection::send_disconnection(&mut socket, &mut ctx)
                                .await
                                .ok();
                            // PIN clear-text vermeyelim — auth_key fingerprint
                            // handshake'i ifşa etmeden log ilişkilendirmeye yeter.
                            bail!(
                                "Peer aktarımı reddetti (status={}). Session fingerprint: {} — PIN eşleşmedi mi?",
                                status,
                                crate::crypto::session_fingerprint(&keys.auth_key)
                            );
                        }
                        // 11) Tüm dosyaları sırayla gönder
                        let mut bytes_sent: i64 = 0;
                        for plan in &plans {
                            info!(
                                "[sender] gönderiliyor: {} ({} bayt) payload_id={}",
                                plan.name, plan.size, plan.payload_id
                            );
                            send_file_chunks(
                                &mut socket,
                                &mut ctx,
                                plan.payload_id,
                                &plan.path,
                                plan.size,
                                &peer_label,
                                &plan.name,
                                bytes_sent,
                                total_bytes,
                            )
                            .await?;
                            bytes_sent += plan.size;
                        }
                        connection::send_disconnection(&mut socket, &mut ctx)
                            .await
                            .ok();
                        let summary = if plans.len() == 1 {
                            plans[0].name.clone()
                        } else {
                            format!("{} dosya", plans.len())
                        };
                        // Stats'i progress güncellemesinden ÖNCE yaz — böylece UI
                        // Completed'ı gördüğünde istatistikler zaten tutarlı olur.
                        {
                            // Save'i lock dışında çalıştır — yavaş diskte UI dondurmasın.
                            let st = state::get();
                            let snap = {
                                let mut s = st.stats.write();
                                for plan in &plans {
                                    s.record_sent(&peer_label, plan.size.max(0) as u64);
                                }
                                s.clone()
                            };
                            let _ = snap.save();
                        }
                        // Bug #31: Completed gösteriminden sonra birkaç saniye içinde
                        // otomatik Idle'a dönsün — kullanıcı pencereyi sonra açtığında
                        // eski "Tamamlandı" banner'ı kalmasın.
                        state::set_progress_completed_auto_idle(
                            summary,
                            state::DEFAULT_COMPLETED_IDLE_DELAY,
                        );
                        info!("[sender] ✓ gönderim tamamlandı");
                        return Ok(());
                    }
                    Some(sh_v1::FrameType::Cancel) => {
                        bail!("Peer aktarımı iptal etti");
                    }
                    other => {
                        info!("[sender] sharing frame: {:?}", other);
                    }
                }
            }
            Some(v1_frame::FrameType::KeepAlive) => {
                let reply = OfflineFrame {
                    version: Some(1),
                    v1: Some(V1Frame {
                        r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                        keep_alive: Some(Default::default()),
                        ..Default::default()
                    }),
                };
                let enc = ctx.encrypt(&reply.encode_to_vec())?;
                frame::write_frame(&mut socket, &enc).await?;
            }
            Some(v1_frame::FrameType::Disconnection) => {
                warn!("[sender] peer disconnect");
                bail!("peer beklenmedik biçimde bağlantıyı kesti");
            }
            other => {
                info!("[sender] beklenmeyen: {:?}", other);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_file_chunks(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    payload_id: i64,
    path: &Path,
    file_size: i64,
    peer_label: &str,
    file_name: &str,
    bytes_sent_before: i64,
    total_bytes: i64,
) -> Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut offset: i64 = 0;
    let mut hasher = Sha256::new();

    loop {
        if state::is_cancelled() {
            bail!("chunk gönderim sırasında iptal");
        }
        let n = file.read(&mut buf).await?;
        if n == 0 {
            let last = wrap_payload_transfer(payload_id, file_size, offset, 1, Vec::new());
            let enc = ctx.encrypt(&last.encode_to_vec())?;
            frame::write_frame(socket, &enc).await?;
            let digest = hasher.finalize();
            let sha_hex = hex::encode(digest);
            info!(
                "[sender] {} gönderildi — SHA-256: {}",
                file_name,
                crate::log_redact::sha_short(&sha_hex)
            );
            break;
        }
        hasher.update(&buf[..n]);
        let body = buf[..n].to_vec();
        let wrapped = wrap_payload_transfer(payload_id, file_size, offset, 0, body);
        let enc = ctx.encrypt(&wrapped.encode_to_vec())?;
        frame::write_frame(socket, &enc).await?;
        offset += n as i64;

        // İlerleme yüzdesi: kümülatif (tüm dosyalar toplu).
        // total_bytes == 0 entry point'te bail ediliyor (Bug #30); yine de
        // `compute_percent` defansif olarak 0/0 ve overflow'u ele alır.
        if let Some(percent) = compute_percent(bytes_sent_before, offset, total_bytes) {
            state::set_progress(ProgressState::Receiving {
                device: peer_label.to_string(),
                file: file_name.to_string(),
                percent,
            });
        }
    }
    Ok(())
}

fn wrap_payload_transfer(
    id: i64,
    total_size: i64,
    offset: i64,
    flags: i32,
    body: Vec<u8>,
) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(ptf::PacketType::Data as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(id),
                    r#type: Some(PayloadType::File as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    ..Default::default()
                }),
                payload_chunk: Some(PayloadChunk {
                    offset: Some(offset),
                    flags: Some(flags),
                    body: Some(body),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn build_introduction_multi(plans: &[PlannedFile]) -> SharingFrame {
    let files: Vec<FileMetadata> = plans
        .iter()
        .map(|p| FileMetadata {
            name: Some(p.name.clone()),
            r#type: Some(FileKind::Unknown as i32),
            payload_id: Some(p.payload_id),
            size: Some(p.size),
            mime_type: Some(guess_mime(&p.name).to_string()),
            ..Default::default()
        })
        .collect();
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Introduction as i32),
            introduction: Some(IntroductionFrame {
                file_metadata: files,
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn guess_mime(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "txt" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

/// Kümülatif byte'lardan [0, 100] aralığında yüzde hesaplar.
///
/// Döner `None` olursa hesap yapılmadı demektir (sıfıra bölme, taşma vb.) —
/// UI'a yeni bir progress update gönderilmez, eski değer kalır.
///
/// - `total` sıfır ya da negatifse `None`: anlamlı bir yüzde yok.
/// - Ara çarpım `i64` taşarsa `None`: dev dosyalarda savunma.
/// - Sonuç `[0, 100]` aralığına `clamp` edilir (floating-point olmadan).
fn compute_percent(bytes_before: i64, offset: i64, total: i64) -> Option<u8> {
    if total <= 0 {
        return None;
    }
    let cumulative = bytes_before.checked_add(offset)?;
    let product = cumulative.checked_mul(100)?;
    let raw = product.checked_div(total)?;
    Some(raw.clamp(0, 100) as u8)
}

fn build_connection_request(our_name: &str) -> OfflineFrame {
    let endpoint_id = config::random_endpoint_id();
    let endpoint_info = config::endpoint_info(our_name);

    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::ConnectionRequest as i32),
            connection_request: Some(ConnectionRequestFrame {
                endpoint_id: Some(
                    std::str::from_utf8(&endpoint_id)
                        .unwrap_or("HEKA")
                        .to_string(),
                ),
                endpoint_name: Some(our_name.to_string()),
                endpoint_info: Some(endpoint_info),
                mediums: vec![Medium::WifiLan as i32],
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bug #30: total == 0 durumunda yüzde hesaplanmaz → panic/NaN riski yok.
    #[test]
    fn compute_percent_total_zero_returns_none() {
        assert_eq!(compute_percent(0, 0, 0), None);
        assert_eq!(compute_percent(100, 50, 0), None);
    }

    // Bug #30 kenar durum: negatif total (kurallara aykırı veri) sessizce atlanır.
    #[test]
    fn compute_percent_negative_total_returns_none() {
        assert_eq!(compute_percent(0, 0, -1), None);
    }

    #[test]
    fn compute_percent_basic_progression() {
        // 0/1000 = 0%
        assert_eq!(compute_percent(0, 0, 1000), Some(0));
        // 500/1000 = 50%
        assert_eq!(compute_percent(0, 500, 1000), Some(50));
        // 1000/1000 = 100%
        assert_eq!(compute_percent(500, 500, 1000), Some(100));
    }

    #[test]
    fn compute_percent_clamps_to_100() {
        // Offset total'dan büyükse (patolojik giriş) sonuç 100'e clamp edilir,
        // asla 100'ü aşmaz.
        assert_eq!(compute_percent(0, 10_000, 1000), Some(100));
        assert_eq!(compute_percent(2000, 0, 1000), Some(100));
    }

    #[test]
    fn compute_percent_overflow_safe_on_huge_values() {
        // cumulative * 100 i64'u taşıracaksa None; panic YOK.
        // i64::MAX / 100 + 1 → çarparken kesin taşar.
        let huge = (i64::MAX / 100) + 1;
        assert_eq!(compute_percent(huge, 0, i64::MAX), None);
    }

    #[test]
    fn compute_percent_large_realistic_transfer() {
        // 60 GB transfer simülasyonu — overflow olmadan doğru yüzde.
        let total: i64 = 60 * 1024 * 1024 * 1024;
        let half = total / 2;
        assert_eq!(compute_percent(0, half, total), Some(50));
        assert_eq!(compute_percent(half, half, total), Some(100));
    }

    #[test]
    fn guess_mime_known_and_unknown() {
        assert_eq!(guess_mime("foto.jpg"), "image/jpeg");
        assert_eq!(guess_mime("FOTO.JPEG"), "image/jpeg");
        assert_eq!(guess_mime("video.mp4"), "video/mp4");
        assert_eq!(guess_mime("belge.pdf"), "application/pdf");
        assert_eq!(guess_mime("bilinmiyor.xyz"), "application/octet-stream");
        assert_eq!(guess_mime("uzantisiz"), "application/octet-stream");
    }
}
