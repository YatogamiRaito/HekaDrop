//! Inbound Nearby/Quick Share bağlantı state machine'i.
//!
//! Akış:
//!   1) Plain ConnectionRequest                       (peer → us)
//!   2) UKEY2 ClientInit                              (peer → us)
//!   3) UKEY2 ServerInit                              (us   → peer)
//!   4) UKEY2 ClientFinished                          (peer → us)    [anahtarlar türetilir]
//!   5) Plain ConnectionResponse                      (peer → us)
//!   6) Plain ConnectionResponse (Accept)             (us   → peer)
//!   7) Şifreli loop — tüm sonraki frame'ler SecureMessage katmanından geçer.

use crate::frame;
use crate::location::nearby::connections::{
    os_info::OsType,
    payload_transfer_frame::{
        self as ptf, payload_header::PayloadType, PayloadChunk, PayloadHeader,
    },
    v1_frame, ConnectionResponseFrame, OfflineFrame, OsInfo, PayloadTransferFrame, V1Frame,
};
use crate::payload::{CompletedPayload, PayloadAssembler};
use crate::secure::SecureCtx;
use crate::sharing::nearby::{
    connection_response_frame::Status as ConsentStatus, frame::Version as ShVersion,
    paired_key_result_frame::Status as PkrStatus, text_metadata::Type as TextType,
    v1_frame as sh_v1, ConnectionResponseFrame as ShConsent, Frame as SharingFrame,
    PairedKeyEncryptionFrame, PairedKeyResultFrame, V1Frame as ShV1Frame,
};
use crate::state::{self, HistoryItem, ProgressState};
use crate::ui;
use crate::ukey2;
use anyhow::{anyhow, Context, Result};
use prost::Message;
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::TcpStream;
use tracing::{info, warn};

pub async fn handle(mut socket: TcpStream, peer: SocketAddr) -> Result<()> {
    // 1) plain ConnectionRequest
    let req = frame::read_frame(&mut socket)
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
    let trusted_early = state::get()
        .settings
        .read()
        .is_trusted(&remote_name, &remote_id);
    if !trusted_early {
        let st = state::get();
        if st.rate_limiter.check_and_record(peer.ip()) {
            warn!(
                "[{}] rate limit aşıldı (60 sn pencerede >10 bağlantı), reddediliyor",
                peer
            );
            return Err(anyhow!(
                "rate limit: aynı IP'den çok fazla bağlantı denemesi"
            ));
        }
    } else {
        info!("[{}] trusted cihaz — rate limit uygulanmadı", peer);
    }

    // 2) UKEY2 ClientInit
    let ci = frame::read_frame(&mut socket)
        .await
        .context("Ukey2ClientInit okunamadı")?;
    let state = ukey2::process_client_init(&ci).context("ClientInit")?;

    // 3) UKEY2 ServerInit
    frame::write_frame(&mut socket, &state.server_init_bytes)
        .await
        .context("ServerInit yazılamadı")?;

    // 4) UKEY2 ClientFinished
    let cf = frame::read_frame(&mut socket)
        .await
        .context("Ukey2ClientFinished okunamadı")?;
    let keys = ukey2::process_client_finish(&cf, &state).context("ClientFinish")?;
    info!("[{}] ✓ UKEY2 tamam — PIN: {}", peer, keys.pin_code);

    // 5) plain ConnectionResponse (karşı taraftan)
    let resp_in = frame::read_frame(&mut socket)
        .await
        .context("peer ConnectionResponse okunamadı")?;
    let peer_resp =
        OfflineFrame::decode(resp_in.as_ref()).context("peer ConnectionResponse decode")?;
    info!(
        "[{}] peer ConnectionResponse → tip={:?}",
        peer,
        peer_resp.v1.as_ref().and_then(|v| v.r#type)
    );

    // 6) plain ConnectionResponse (bizden Accept)
    let our_resp = build_connection_response_accept();
    frame::write_frame(&mut socket, &our_resp.encode_to_vec())
        .await
        .context("ConnectionResponse yazılamadı")?;
    info!("[{}] bizim ConnectionResponse (Accept) gönderildi", peer);

    // 7) Şifreli loop
    let mut ctx = SecureCtx::from_keys(&keys);
    let mut assembler = PayloadAssembler::new();

    // 8) Bizim PairedKeyEncryption'ı hemen gönder (peer'a aynı anda gönderir)
    send_sharing_frame(&mut socket, &mut ctx, &build_paired_key_encryption()).await?;
    info!("[{}] PairedKeyEncryption gönderildi", peer);

    let mut sent_paired_result = false;
    let mut accepted = false;
    let mut pending_texts: HashMap<i64, TextType> = HashMap::new();
    let mut pending_names: HashMap<i64, String> = HashMap::new();
    let remote_name_shared = remote_name.clone();
    let remote_id_shared = remote_id.clone();
    let pin_shared = keys.pin_code.clone();
    state::clear_cancel();

    loop {
        if state::is_cancelled() {
            info!(
                "[{}] kullanıcı iptal — Cancel + Disconnect gönderiliyor",
                peer
            );
            let cancel = build_sharing_cancel();
            send_sharing_frame(&mut socket, &mut ctx, &cancel)
                .await
                .ok();
            send_disconnection(&mut socket, &mut ctx).await.ok();
            cleanup_transfer_state(
                &peer,
                &mut assembler,
                &mut pending_names,
                &mut pending_texts,
            );
            ui::notify("HekaDrop", "Aktarım iptal edildi");
            break;
        }

        let raw = match frame::read_frame(&mut socket).await {
            Ok(b) => b,
            Err(e) => {
                warn!("[{}] bağlantı sonlandı: {:?}", peer, e);
                break;
            }
        };
        let inner = match ctx.decrypt(&raw) {
            Ok(b) => b,
            Err(e) => {
                warn!("[{}] decrypt hata: {:?}", peer, e);
                break;
            }
        };

        let offline = OfflineFrame::decode(inner.as_ref()).context("iç OfflineFrame")?;
        let v1 = match offline.v1 {
            Some(v) => v,
            None => continue,
        };
        let ftype = v1
            .r#type
            .and_then(|t| v1_frame::FrameType::try_from(t).ok());

        match ftype {
            Some(v1_frame::FrameType::PayloadTransfer) => {
                let pt = v1
                    .payload_transfer
                    .ok_or_else(|| anyhow!("payload_transfer yok"))?;

                // Canlı ilerleme (file payload'lar için)
                if let (Some(header), Some(chunk)) =
                    (pt.payload_header.as_ref(), pt.payload_chunk.as_ref())
                {
                    let is_file = header.r#type
                        == Some(
                            crate::location::nearby::connections::payload_transfer_frame::payload_header::PayloadType::File as i32,
                        );
                    if is_file {
                        let id = header.id.unwrap_or(0);
                        let total = header.total_size.unwrap_or(0);
                        let offset = chunk.offset.unwrap_or(0);
                        let body_len = chunk.body.as_ref().map(|b| b.len()).unwrap_or(0) as i64;
                        let written = offset + body_len;
                        if total > 0 {
                            let percent = ((written * 100) / total).clamp(0, 100) as u8;
                            if let Some(name) = pending_names.get(&id).cloned() {
                                state::set_progress(ProgressState::Receiving {
                                    device: remote_name_shared.clone(),
                                    file: name,
                                    percent,
                                });
                            }
                        }
                    }
                }

                if let Some(done) = assembler.ingest(&pt)? {
                    match done {
                        CompletedPayload::Bytes { id, data } => {
                            // Metin/URL payload mı?
                            if let Some(kind) = pending_texts.remove(&id) {
                                handle_text_payload(&peer, kind, &data);
                                continue;
                            }
                            if let Ok(sharing) = SharingFrame::decode(&data[..]) {
                                let outcome = handle_sharing_frame(
                                    &peer,
                                    &mut socket,
                                    &mut ctx,
                                    &mut assembler,
                                    &sharing,
                                    &mut sent_paired_result,
                                    &remote_name_shared,
                                    &remote_id_shared,
                                    &pin_shared,
                                    &mut accepted,
                                    &mut pending_texts,
                                    &mut pending_names,
                                )
                                .await?;
                                if outcome == FlowOutcome::Disconnect {
                                    send_disconnection(&mut socket, &mut ctx).await.ok();
                                    cleanup_transfer_state(
                                        &peer,
                                        &mut assembler,
                                        &mut pending_names,
                                        &mut pending_texts,
                                    );
                                    break;
                                }
                            }
                        }
                        CompletedPayload::File {
                            id,
                            path,
                            total_size,
                            sha256,
                        } => {
                            pending_names.remove(&id);
                            let sha_hex = hex::encode(sha256);
                            info!(
                                "[{}] ✓ {} alındı — SHA-256: {}",
                                peer,
                                path.display(),
                                sha_hex
                            );
                            {
                                let st = state::get();
                                let mut s = st.stats.write();
                                s.record_received(&remote_name_shared, total_size as u64);
                                let _ = s.save();
                            }
                            let file_name = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("dosya")
                                .to_string();
                            state::set_progress(ProgressState::Completed {
                                file: file_name.clone(),
                            });
                            state::push_history(HistoryItem {
                                file_name: file_name.clone(),
                                path: path.clone(),
                                size: total_size,
                                device: remote_name_shared.clone(),
                                when: std::time::SystemTime::now(),
                                sha256_short: sha_hex.chars().take(16).collect(),
                            });
                            info!(
                                "[{}] ✓ kaydedildi: {} ({} bayt)",
                                peer,
                                path.display(),
                                total_size
                            );
                            ui::notify_file_received(
                                "HekaDrop",
                                &format!(
                                    "İndirildi: {} ({})",
                                    path.file_name().and_then(|n| n.to_str()).unwrap_or("dosya"),
                                    human_size(total_size)
                                ),
                                path.clone(),
                            );
                        }
                    }
                }
            }
            Some(v1_frame::FrameType::KeepAlive) => {
                // Basit ack: aynı KeepAlive'ı geri gönder.
                let reply = OfflineFrame {
                    version: Some(1),
                    v1: Some(V1Frame {
                        r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                        keep_alive: Some(Default::default()),
                        ..Default::default()
                    }),
                };
                let enc = ctx.encrypt(&reply.encode_to_vec());
                frame::write_frame(&mut socket, &enc).await?;
            }
            Some(v1_frame::FrameType::Disconnection) => {
                info!("[{}] karşı taraf disconnect", peer);
                break;
            }
            other => {
                info!("[{}] beklenmeyen frame tipi: {:?}", peer, other);
            }
        }
    }

    // Loop'tan nasıl çıkıldığından bağımsız olarak artakalan yarım dosyaları,
    // pending haritaları ve global state bayraklarını temizle. Böylece bir
    // sonraki bağlantı tamamen temiz bir state ile başlar (Bug #28).
    cleanup_transfer_state(
        &peer,
        &mut assembler,
        &mut pending_names,
        &mut pending_texts,
    );

    Ok(())
}

/// Yarım kalan alıcı state'ini — hem yerel hem global — temizler.
///
/// Reject, kullanıcı Cancel, peer Disconnect, I/O hatası veya socket
/// kopması durumlarının hepsinde güvenli biçimde çağrılır; idempotent'tir.
/// Yaptığı işler:
///   * `pending_names` içindeki her payload_id için `PayloadAssembler::cancel`
///     çağrılır — yarım yazılmış dosyalar ve açık dosya kulpları temizlenir,
///     disk sızıntısı önlenir.
///   * `pending_texts` ve `pending_names` tamamen boşaltılır.
///   * Global `cancel_flag` sıfırlanır (bir sonraki bağlantıyı etkilemesin).
///   * Progress durumu `Idle` yapılır (UI "alınıyor…" takılı kalmasın).
fn cleanup_transfer_state(
    peer: &SocketAddr,
    assembler: &mut PayloadAssembler,
    pending_names: &mut HashMap<i64, String>,
    pending_texts: &mut HashMap<i64, TextType>,
) {
    let n = drain_pending(assembler, pending_names, pending_texts);
    state::clear_cancel();
    state::set_progress(ProgressState::Idle);

    if n > 0 {
        info!(
            "[{}] cleanup: {} yarım dosya silindi, state Idle'a döndürüldü",
            peer, n
        );
    } else {
        tracing::debug!("[{}] cleanup: state Idle'a döndürüldü", peer);
    }
}

/// `cleanup_transfer_state`'in saf (global-state'siz) çekirdeği — birim
/// testlenebilsin diye ayrıldı. Yarım kalan dosyaları iptal eder ve iki
/// haritayı boşaltır; temizlenen yarım dosya sayısını döner.
fn drain_pending(
    assembler: &mut PayloadAssembler,
    pending_names: &mut HashMap<i64, String>,
    pending_texts: &mut HashMap<i64, TextType>,
) -> usize {
    // pending_names'teki id'ler: Introduction sırasında "kabul edildi" kaydedilmiş
    // ama henüz CompletedPayload::File olarak tamamlanmamış dosyalar. Bunları
    // assembler'a cancel ettirmek yarım dosya + açık handle'ı siler.
    let ids: Vec<i64> = pending_names.keys().copied().collect();
    let n = ids.len();
    for id in ids {
        assembler.cancel(id);
    }
    pending_names.clear();
    pending_texts.clear();
    n
}

#[derive(PartialEq, Eq)]
enum FlowOutcome {
    Continue,
    Disconnect,
}

#[allow(clippy::too_many_arguments)]
async fn handle_sharing_frame(
    peer: &SocketAddr,
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    assembler: &mut PayloadAssembler,
    frame: &SharingFrame,
    sent_paired_result: &mut bool,
    remote_name: &str,
    remote_id: &str,
    pin_code: &str,
    accepted_flag: &mut bool,
    pending_texts: &mut HashMap<i64, TextType>,
    pending_names: &mut HashMap<i64, String>,
) -> Result<FlowOutcome> {
    let v1 = frame.v1.as_ref().ok_or_else(|| anyhow!("sharing v1 yok"))?;
    let t = v1.r#type.and_then(|t| sh_v1::FrameType::try_from(t).ok());
    match t {
        Some(sh_v1::FrameType::PairedKeyEncryption) if !*sent_paired_result => {
            send_sharing_frame(socket, ctx, &build_paired_key_result()).await?;
            *sent_paired_result = true;
        }
        Some(sh_v1::FrameType::PairedKeyResult) => {}
        Some(sh_v1::FrameType::Introduction) => {
            let intro = v1
                .introduction
                .as_ref()
                .ok_or_else(|| anyhow!("introduction yok"))?;
            let file_count = intro.file_metadata.len();
            let text_count = intro.text_metadata.len();
            info!(
                "[{}] Introduction: {} dosya, {} metin",
                peer, file_count, text_count
            );

            let mut summaries: Vec<ui::FileSummary> = Vec::new();
            let mut planned_files: Vec<(i64, std::path::PathBuf, String)> = Vec::new();
            for f in &intro.file_metadata {
                let name = f.name.clone().unwrap_or_else(|| "dosya".into());
                let size = f.size.unwrap_or(0);
                summaries.push(ui::FileSummary {
                    name: name.clone(),
                    size,
                });
                if let Some(pid) = f.payload_id {
                    planned_files.push((pid, unique_downloads_path(&name)?, name));
                }
            }

            let mut planned_texts: Vec<(i64, TextType)> = Vec::new();
            for tm in &intro.text_metadata {
                let kind = TextType::try_from(tm.r#type.unwrap_or(0)).unwrap_or(TextType::Unknown);
                if let Some(pid) = tm.payload_id {
                    planned_texts.push((pid, kind));
                }
            }

            // Karar mantığı:
            //   1) Trusted device → dialog atla, otomatik kabul
            //   2) Settings.auto_accept → dialog atla, otomatik kabul
            //   3) Aksi halde dialog göster (3 seçenek: reddet/kabul/kabul+güven)
            let trusted = state::get()
                .settings
                .read()
                .is_trusted(remote_name, remote_id);
            let auto_accept = state::get().settings.read().auto_accept;

            let decision = if trusted {
                info!("[{}] trusted cihaz → otomatik kabul", peer);
                ui::AcceptResult::Accept
            } else if auto_accept {
                info!("[{}] settings.auto_accept=true → otomatik kabul", peer);
                ui::AcceptResult::Accept
            } else {
                ui::prompt_accept(remote_name, pin_code, &summaries, text_count)
                    .await
                    .unwrap_or(ui::AcceptResult::Reject)
            };

            let ok = !matches!(decision, ui::AcceptResult::Reject);
            *accepted_flag = ok;

            if matches!(decision, ui::AcceptResult::AcceptAndTrust) {
                let st = state::get();
                let mut s = st.settings.write();
                s.add_trusted(remote_name, remote_id);
                let _ = s.save();
                info!(
                    "[{}] cihaz trusted listeye eklendi: {} (id: {})",
                    peer,
                    remote_name,
                    if remote_id.is_empty() {
                        "<yok>"
                    } else {
                        remote_id
                    }
                );
                ui::notify(
                    "HekaDrop",
                    &format!("{} artık güvenilir cihaz", remote_name),
                );
            }

            if ok {
                for (pid, path, display_name) in planned_files {
                    assembler.register_file_destination(pid, path);
                    pending_names.insert(pid, display_name);
                }
                for (pid, kind) in planned_texts {
                    pending_texts.insert(pid, kind);
                }
                send_sharing_frame(socket, ctx, &build_consent_accept()).await?;
                info!("[{}] ✓ kullanıcı kabul etti", peer);
            } else {
                send_sharing_frame(socket, ctx, &build_consent_reject()).await?;
                info!("[{}] ✗ kullanıcı reddetti", peer);
                ui::notify("HekaDrop", &format!("{}: aktarım reddedildi", remote_name));
                return Ok(FlowOutcome::Disconnect);
            }
        }
        Some(sh_v1::FrameType::Cancel) => {
            info!("[{}] peer cancel", peer);
            return Ok(FlowOutcome::Disconnect);
        }
        _ => {}
    }
    Ok(FlowOutcome::Continue)
}

fn handle_text_payload(peer: &SocketAddr, kind: TextType, data: &[u8]) {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            warn!("[{}] UTF-8 olmayan metin payload", peer);
            return;
        }
    };
    match kind {
        TextType::Url => {
            crate::platform::open_url(&text);
            info!("[{}] URL açıldı: {}", peer, text);
            ui::notify("HekaDrop", &format!("URL açıldı: {}", preview(&text, 80)));
        }
        _ => {
            crate::platform::copy_to_clipboard(&text);
            info!(
                "[{}] metin panoya kopyalandı ({} karakter)",
                peer,
                text.len()
            );
            ui::notify(
                "HekaDrop",
                &format!("Metin panoya kopyalandı: {}", preview(&text, 80)),
            );
        }
    }
}

fn preview(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{}…", truncated)
    }
}

pub(crate) async fn send_disconnection(socket: &mut TcpStream, ctx: &mut SecureCtx) -> Result<()> {
    let f = OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::Disconnection as i32),
            disconnection: Some(Default::default()),
            ..Default::default()
        }),
    };
    let enc = ctx.encrypt(&f.encode_to_vec());
    frame::write_frame(socket, &enc).await?;
    Ok(())
}

fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut n = bytes as f64;
    let mut i = 0;
    while n >= 1024.0 && i < UNITS.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", n, UNITS[i])
    }
}

fn unique_downloads_path(name: &str) -> Result<PathBuf> {
    let base = state::get().settings.read().resolved_download_dir();
    std::fs::create_dir_all(&base).ok();

    let mut candidate = base.join(name);
    if !candidate.exists() {
        return Ok(candidate);
    }
    let (stem, ext) = split_name(name);
    let mut n = 1;
    loop {
        let filename = if ext.is_empty() {
            format!("{} ({})", stem, n)
        } else {
            format!("{} ({}).{}", stem, n, ext)
        };
        candidate = base.join(filename);
        if !candidate.exists() {
            return Ok(candidate);
        }
        n += 1;
    }
}

fn split_name(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(idx) if idx > 0 && idx < name.len() - 1 => (&name[..idx], &name[idx + 1..]),
        _ => (name, ""),
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

pub(crate) fn build_paired_key_encryption() -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::PairedKeyEncryption as i32),
            paired_key_encryption: Some(PairedKeyEncryptionFrame {
                secret_id_hash: Some(random_bytes(6)),
                signed_data: Some(random_bytes(72)),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) fn build_paired_key_result() -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::PairedKeyResult as i32),
            paired_key_result: Some(PairedKeyResultFrame {
                status: Some(PkrStatus::Unable as i32),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn build_consent_accept() -> SharingFrame {
    build_consent(ConsentStatus::Accept)
}

fn build_consent_reject() -> SharingFrame {
    build_consent(ConsentStatus::Reject)
}

pub(crate) fn build_sharing_cancel() -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Cancel as i32),
            ..Default::default()
        }),
    }
}

fn build_consent(status: ConsentStatus) -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Response as i32),
            connection_response: Some(ShConsent {
                status: Some(status as i32),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

pub(crate) async fn send_sharing_frame(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    sharing: &SharingFrame,
) -> Result<()> {
    let body = sharing.encode_to_vec();
    let payload_id: i64 = rand::thread_rng().next_u64() as i64;
    let total = body.len() as i64;

    // İlk chunk: tam gövde, offset=0, flags=0
    let first = wrap_payload_transfer(payload_id, total, 0, 0, body.clone());
    let enc1 = ctx.encrypt(&first.encode_to_vec());
    frame::write_frame(socket, &enc1).await?;

    // Son chunk: boş gövde, flags=1 (last)
    let last = wrap_payload_transfer(payload_id, total, total, 1, Vec::new());
    let enc2 = ctx.encrypt(&last.encode_to_vec());
    frame::write_frame(socket, &enc2).await?;
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
                    r#type: Some(PayloadType::Bytes as i32),
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

pub(crate) fn build_connection_response_accept() -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::ConnectionResponse as i32),
            connection_response: Some(ConnectionResponseFrame {
                response: Some(1),
                os_info: Some(OsInfo {
                    r#type: Some(OsType::Apple as i32),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn parse_remote_name(endpoint_info: &[u8]) -> Option<String> {
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
    use std::io::Write;

    // std::env::temp_dir + nanos-based path ile küçük bir geçici dosya yolu döndürür.
    // Harici `tempfile` crate'ini projeye eklememek için minimal shim.
    fn unique_tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // process id'yi de karıştır ki paralel test thread'leri çakışmasın.
        p.push(format!(
            "hekadrop-test-{}-{}-{}",
            std::process::id(),
            nanos,
            name
        ));
        p
    }

    #[test]
    fn split_name_handles_no_extension() {
        assert_eq!(split_name("README"), ("README", ""));
    }

    #[test]
    fn split_name_handles_dotfile() {
        // Baş harfte nokta → extension yoktur (stem=".env").
        assert_eq!(split_name(".env"), (".env", ""));
    }

    #[test]
    fn split_name_handles_trailing_dot() {
        // Sonda nokta → extension boş kabul edilir (tam adın kendisi stem).
        assert_eq!(split_name("weird."), ("weird.", ""));
    }

    #[test]
    fn split_name_basic_extension() {
        assert_eq!(split_name("photo.jpg"), ("photo", "jpg"));
    }

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

    #[test]
    fn drain_pending_bos_icin_sifir_dondurur() {
        let mut asm = PayloadAssembler::new();
        let mut names: HashMap<i64, String> = HashMap::new();
        let mut texts: HashMap<i64, TextType> = HashMap::new();
        assert_eq!(drain_pending(&mut asm, &mut names, &mut texts), 0);
        assert!(names.is_empty());
        assert!(texts.is_empty());
    }

    #[test]
    fn drain_pending_yarim_kalan_dosyalari_diskten_siler() {
        // Gerçekçi senaryo: kullanıcı introduction'ı kabul etti, assembler
        // dosya hedefini kaydetti (fakat henüz hiç chunk gelmedi) → cancel
        // edildiğinde pending_destination temizlenmeli.
        let mut asm = PayloadAssembler::new();
        let mut names: HashMap<i64, String> = HashMap::new();
        let mut texts: HashMap<i64, TextType> = HashMap::new();

        let p1 = unique_tmp("a.bin");
        let p2 = unique_tmp("b.bin");
        // Fiziksel dosyaları oluşturalım — reject sonrası silindiklerini doğrulamak için.
        {
            let mut f1 = std::fs::File::create(&p1).unwrap();
            f1.write_all(b"half").unwrap();
            let mut f2 = std::fs::File::create(&p2).unwrap();
            f2.write_all(b"half").unwrap();
        }
        asm.register_file_destination(101, p1.clone());
        asm.register_file_destination(202, p2.clone());
        names.insert(101, "a.bin".into());
        names.insert(202, "b.bin".into());
        texts.insert(303, TextType::Text);

        let cleaned = drain_pending(&mut asm, &mut names, &mut texts);

        assert_eq!(cleaned, 2, "iki yarım dosya temizlenmeliydi");
        assert!(names.is_empty(), "pending_names sıfırlanmalı");
        assert!(texts.is_empty(), "pending_texts sıfırlanmalı");
        // NOT: `register_file_destination` çağrılmış ama hiç chunk gelmemiş dosyalar
        // için `assembler.cancel(id)` yalnızca haritadan kaldırır — diskte
        // file yoktur (çünkü biz elle oluşturduk). Burada test dosyalarını
        // temizlemek test hijyeni için:
        std::fs::remove_file(&p1).ok();
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn drain_pending_acik_dosya_sinkini_siler() {
        // İlk chunk gelmiş → dosya create edilmiş → sonra reject/cancel.
        let mut asm = PayloadAssembler::new();
        let mut names: HashMap<i64, String> = HashMap::new();
        let mut texts: HashMap<i64, TextType> = HashMap::new();

        let p = unique_tmp("partial.bin");
        asm.register_file_destination(777, p.clone());
        names.insert(777, "partial.bin".into());

        // İlk chunk'ı simüle et (100 bayt toplam, 10 bayt body, last=false).
        let chunk_frame = wrap_payload_transfer(777, 100, 0, 0, vec![0xAB; 10])
            .v1
            .unwrap()
            .payload_transfer
            .unwrap();
        // PayloadHeader'daki tipi File'a çevir.
        let mut chunk_frame = chunk_frame;
        if let Some(h) = chunk_frame.payload_header.as_mut() {
            h.r#type = Some(PayloadType::File as i32);
        }
        asm.ingest(&chunk_frame).unwrap();

        assert!(p.exists(), "assembler ilk chunk'ı diske yazmış olmalı");

        let cleaned = drain_pending(&mut asm, &mut names, &mut texts);
        assert_eq!(cleaned, 1);
        assert!(
            !p.exists(),
            "yarım kalan dosya reject sonrası silinmiş olmalı"
        );
    }
}
