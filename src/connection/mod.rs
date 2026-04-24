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
//!
//! Bu dosya yalnız dispatch katmanıdır; detay alt-modüllere dağılmıştır:
//!   * `request`  — plain ConnectionRequest okuma + rate limit
//!   * `frames`   — frame builder/sender yardımcıları (sender.rs da kullanır)
//!   * `consent`  — sharing frame dispatcher + Introduction/consent mantığı
//!   * `sharing`  — şifreli loop yardımcıları (metin payload, cleanup)
//!   * `sanitize` — dosya adı / URL sanitizasyonu + benzersiz indirme yolu
//!   * `errors`   — UKEY2 hata sınıflandırma

pub(crate) mod consent;
pub(crate) mod errors;
pub(crate) mod frames;
pub(crate) mod request;
pub(crate) mod sanitize;
pub(crate) mod sharing;

// Dış modüller (sender.rs) bu yardımcıları `connection::foo` ile kullanır.
pub(crate) use frames::{
    build_connection_response_accept, build_paired_key_encryption, build_paired_key_result,
    build_sharing_cancel, send_disconnection, send_sharing_frame,
};

use crate::frame;
use crate::location::nearby::connections::{v1_frame, OfflineFrame, V1Frame};
use crate::payload::{CompletedPayload, PayloadAssembler};
use crate::secure::SecureCtx;
use crate::sharing::nearby::{text_metadata::Type as TextType, Frame as SharingFrame};
use crate::state::{self, HistoryItem, ProgressState};
use crate::ui;
use crate::ukey2;
use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{info, warn};

use self::consent::{handle_sharing_frame, FlowOutcome};
use self::errors::classify_handshake_error;
use self::request::read_connection_request;
use self::sharing::{cleanup_transfer_state, handle_text_payload, human_size};

pub async fn handle(mut socket: TcpStream, peer: SocketAddr) -> Result<()> {
    // `TransferGuard::new()` içinde auto clear_cancel — bu bağlantıya özel
    // child token hem taze root'a hem de scope sonunda active_transfers
    // map'inden otomatik temizliğe (early-return yollarında bile) garanti verir.
    let guard = state::TransferGuard::new(format!("in:{}", peer));
    let cancel = guard.token.clone();

    // 1) Plain ConnectionRequest + rate limit (trusted muaf).
    let intro = read_connection_request(&mut socket, peer).await?;
    let remote_name = intro.remote_name;
    let remote_id = intro.remote_id;

    // 2) UKEY2 ClientInit — 4) UKEY2 ClientFinished
    //
    // UX (Issue: "handshake hatası sessiz kalıyor"): bu adımlarda hata
    // oluşursa tek başına log yetersiz — kullanıcı karşı cihazda "PIN
    // uyuşmadı mı, timeout mu, protokol mü düşürüldü" ayırt edemiyor.
    // Tüm ukey2 handshake fallible adımlarını bir async block'a sarıp
    // Err yolunda `classify_handshake_error` ile uygun i18n bildirim
    // tetikliyoruz, sonra hata yukarı propagate edilir (davranış değişmez,
    // sadece kullanıcı bilgilendirilir).
    let handshake: Result<(ukey2::ServerInitResult, ukey2::DerivedKeys)> = async {
        let ci = frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT)
            .await
            .context("Ukey2ClientInit okunamadı")?;
        let st = ukey2::process_client_init(&ci).context("ClientInit")?;

        // 3) UKEY2 ServerInit
        frame::write_frame(&mut socket, &st.server_init_bytes)
            .await
            .context("ServerInit yazılamadı")?;

        // 4) UKEY2 ClientFinished
        let cf = frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT)
            .await
            .context("Ukey2ClientFinished okunamadı")?;
        let k = ukey2::process_client_finish(&cf, &st).context("ClientFinish")?;
        Ok((st, k))
    }
    .await;

    let (_state, keys) = match handshake {
        Ok(v) => v,
        Err(e) => {
            let key = classify_handshake_error(&e);
            ui::notify(crate::i18n::t("notify.app_name"), crate::i18n::t(key));
            return Err(e);
        }
    };
    // SECURITY: PIN clear-text log'a yazılmaz. 4-basamaklı PIN'in hash'i
    // brute-force olur; onun yerine 256-bit auth_key fingerprint'i
    // kullanıyoruz (bkz. `session_fingerprint`).
    info!(
        "[{}] ✓ UKEY2 tamam — session fingerprint: {}",
        peer,
        crate::crypto::session_fingerprint(&keys.auth_key)
    );

    // 5) plain ConnectionResponse (karşı taraftan)
    let resp_in = frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT)
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
    // Issue #17: peer'ın `secret_id_hash`'i — `PairedKeyEncryption` frame'i
    // alındığında doldurulur; Introduction branch'inde trust kararı için
    // kullanılır. Peer spec'e uymazsa `None` kalır ve legacy fallback
    // devreye girer.
    let mut peer_secret_id_hash: Option<[u8; 6]> = None;

    loop {
        // Steady-loop timeout: peer Quick Share spec'i gereği ~30s'de bir
        // KeepAlive gönderir. 60 sn içinde hiçbir frame gelmezse bağlantıyı
        // ölü kabul ediyoruz — idle TCP task sızıntısını önler.
        //
        // `select!` ile cancel sinyali `read_frame_timeout` tamamlanmasını
        // beklemeden (en kötü 60 sn idle senaryosunda bile) anında algılanır.
        // `read_frame`'in future'ı düştüğünde socket state düşer — yarı
        // okunmuş frame bir daha kullanılmaz çünkü burada bail yolundayız.
        let read_result = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!(
                    "[{}] kullanıcı iptal — Cancel + Disconnect gönderiliyor",
                    peer
                );
                let cf = build_sharing_cancel();
                send_sharing_frame(&mut socket, &mut ctx, &cf).await.ok();
                send_disconnection(&mut socket, &mut ctx).await.ok();
                cleanup_transfer_state(
                    &peer,
                    &mut assembler,
                    &mut pending_names,
                    &mut pending_texts,
                );
                ui::notify(
                    crate::i18n::t("notify.app_name"),
                    crate::i18n::t("notify.transfer_cancelled"),
                );
                break;
            }
            res = frame::read_frame_timeout(&mut socket, frame::STEADY_READ_TIMEOUT) => res,
        };
        let raw = match read_result {
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

                if let Some(done) = assembler.ingest(&pt).await? {
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
                                    &mut peer_secret_id_hash,
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
                                crate::log_redact::path_basename(&path),
                                crate::log_redact::sha_short(&sha_hex)
                            );
                            {
                                // PERF/SAFETY: RwLock write guard altında senkron disk I/O
                                // yapılmamalı — yavaş diskte tüm okuyucular (UI event loop)
                                // bloklanır. Snapshot clone + drop guard + lock-dışı save.
                                //
                                // H#4 privacy: `keep_stats=false` iken RAM'deki Stats yine
                                // güncellenir (UI Tanı sekmesi session boyunca doğru kalsın)
                                // ama disk yazma atlanır. Mevcut stats.json silinmez —
                                // kullanıcı sonradan tekrar açabilir, eski metrik kaybolmaz.
                                let st = state::get();
                                let keep = st.settings.read().keep_stats;
                                let snap_opt = {
                                    let mut s = st.stats.write();
                                    s.record_received(&remote_name_shared, total_size as u64);
                                    if keep {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                };
                                if let Some(snap) = snap_opt {
                                    let _ = snap.save();
                                }
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
                                crate::log_redact::path_basename(&path),
                                total_size
                            );
                            ui::notify_file_received(
                                crate::i18n::t("notify.app_name"),
                                &crate::i18n::tf(
                                    "notify.received",
                                    &[&file_name, &human_size(total_size)],
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
                let enc = ctx.encrypt(&reply.encode_to_vec())?;
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
