//! Inbound Nearby/Quick Share bağlantı state machine'i.
//!
//! Akış:
//!   1) Plain `ConnectionRequest`                       (peer → us)
//!   2) UKEY2 `ClientInit`                              (peer → us)
//!   3) UKEY2 `ServerInit`                              (us   → peer)
//!   4) UKEY2 `ClientFinished`                          (peer → us)    [anahtarlar türetilir]
//!   5) Plain `ConnectionResponse`                      (peer → us)
//!   6) Plain `ConnectionResponse` (Accept)             (us   → peer)
//!   7) Şifreli loop — tüm sonraki frame'ler `SecureMessage` katmanından geçer.

use crate::error::HekaError;
use crate::frame;
use crate::location::nearby::connections::{
    os_info::OsType,
    payload_transfer_frame::{
        self as ptf, payload_header::PayloadType, PayloadChunk, PayloadHeader,
    },
    v1_frame, ConnectionResponseFrame, DisconnectionFrame, KeepAliveFrame, OfflineFrame, OsInfo,
    PayloadTransferFrame, V1Frame,
};
use crate::payload::{CompletedPayload, PayloadAssembler};
use crate::secure::SecureCtx;
use crate::sharing::nearby::{
    connection_response_frame::Status as ConsentStatus, frame::Version as ShVersion,
    paired_key_result_frame::Status as PkrStatus, text_metadata::Type as TextType,
    v1_frame as sh_v1, ConnectionResponseFrame as ShConsent, Frame as SharingFrame,
    PairedKeyEncryptionFrame, PairedKeyResultFrame, V1Frame as ShV1Frame,
};
use crate::state::{self, AppState, HistoryItem, ProgressState};
use crate::ui_port::{AcceptDecision, FileSummary, UiNotification, UiPort};
use crate::ukey2;
use anyhow::{anyhow, Context, Result};
use prost::Message;
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Inbound bağlantı handler'ı için caller tarafından inject edilen
/// platform-bağımlı yardımcılar.
///
/// I-1 (CLAUDE.md): connection core'a taşınınca `crate::platform`
/// (`open_url` / `copy_to_clipboard`) referansı sızmasın diye trait üzerinden
/// dispatch ediyoruz. App-side `PlatformShim` minimal `Send + Sync` impl'i
/// `crate::platform::*` çağrılarına forward eder.
/// RFC-0005 §4 — folder bundle MIME marker. Sender Introduction'da
/// `FileMetadata.mime_type` alanına bunu yazar; receiver bu değer +
/// `FOLDER_STREAM_V1` capability aktif iken bundle extract pipeline'a
/// route eder. Spec: `docs/protocol/folder-payload.md` §4.
pub const FOLDER_BUNDLE_MIME: &str = "application/x-hekadrop-folder";

pub trait PlatformOps: Send + Sync {
    /// Tarayıcıda URL aç (yalnız http/https — caller şema doğrulamasını
    /// üst seviyede yapmıştır; trait kontratı "verileni aç" değildir).
    fn open_url(&self, url: &str);
    /// Sistem clipboard'una metin kopyala (UTF-16 doğruluğu platform-side).
    fn copy_to_clipboard(&self, text: &str);
}

pub async fn handle(
    mut socket: TcpStream,
    peer: SocketAddr,
    ui: Arc<dyn UiPort>,
    state: Arc<AppState>,
    platform: Arc<dyn PlatformOps>,
) -> Result<()> {
    // `TransferGuard::new()` içinde auto clear_cancel — bu bağlantıya özel
    // child token hem taze root'a hem de scope sonunda active_transfers
    // map'inden otomatik temizliğe (early-return yollarında bile) garanti verir.
    let guard = state::TransferGuard::new(Arc::clone(&state), format!("in:{peer}"));
    let cancel = guard.token.clone();

    // 1) plain ConnectionRequest
    // SECURITY: Handshake fazındaki tüm frame okumaları slow-loris DoS'a karşı
    // 30 sn timeout ile sarmalanır; aksi halde saldırgan TCP bağlantı açıp
    // veri göndermeden tokio task'ını sonsuza kadar tutabilir.
    let req = frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT)
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

    // Rate limiting — gate'de HERKES'e uygulanır (Issue #17 closure).
    //
    // Eski davranış (v0.5/erken v0.6): peer'ın iddia ettiği `(remote_name,
    // remote_id)` çifti trusted listede varsa `check_and_record` hiç
    // çağrılmaz, rate-limit bypass edilir. Bu alanlar peer-controlled —
    // saldırgan kurbanın trusted listesindeki bir adı + endpoint_id'yi
    // spoof edip 10/60s limit'i aşabilir ve 32-permit `Semaphore`'u
    // handshake-in-progress ile doldurarak meşru peer'ları DoS edebilir.
    //
    // Yeni davranış: gate'de muafiyet yok. Trusted kararı yalnızca
    // `PairedKeyEncryption` sonrası peer'ın secret_id_hash'i doğrulandığında
    // geriye-dönük uygulanır — o noktada `rate_limiter.forget_most_recent`
    // ile bu bağlantının kaydı silinir. Böylece hash-doğrulanmış trusted
    // peer sürekli bağlantılarla throttle olmaz, ama peer-controlled
    // stringlere güvenmeyiz.
    if state.rate_limiter.check_and_record(peer.ip()) {
        warn!(
            "[{}] rate limit aşıldı (60 sn pencerede >10 bağlantı), reddediliyor",
            peer
        );
        return Err(HekaError::RateLimited(peer.to_string()).into());
    }

    // 2-4) UKEY2 handshake. Bir async bloğa sarıp `?`'lerin tüm adımları
    // kapsamasını garantiliyoruz; hata durumunda downcast zinciriyle
    // kullanıcıya uygun i18n key (PIN / timeout / disconnect / insecure)
    // tek noktadan gösterilir (Dalga 2 UX: "sessiz sonlandırma" yerine
    // anlaşılır bildirim).
    let handshake: Result<(ukey2::ServerInitResult, ukey2::DerivedKeys)> = async {
        let ci = frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT)
            .await
            .context("Ukey2ClientInit okunamadı")?;
        let st = ukey2::process_client_init(&ci).context("ClientInit")?;
        frame::write_frame(&mut socket, &st.server_init_bytes)
            .await
            .context("ServerInit yazılamadı")?;
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
            warn!("[{}] UKEY2 handshake başarısız: {:#}", peer, e);
            ui.notify(UiNotification::Toast {
                title_key: "notify.app_name",
                body_key: Some(key),
                body_args: Vec::new(),
            });
            state.set_progress(ProgressState::Idle);
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
    send_sharing_frame(
        &mut socket,
        &mut ctx,
        &build_paired_key_encryption(state.as_ref()),
    )
    .await?;
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

    // RFC-0003 §3.3 capabilities exchange — receiver opportunistic.
    // Peer (sender) HekaDrop-aware ise sender Capabilities frame yollar
    // (sender mDNS'ten ext=1 görünce); receiver burada handle edip kendi
    // Capabilities'ini geri yollar. Legacy peer hiç HekaDropFrame yollamaz
    // → bu alanlar default `legacy()` kalır, transfer normal Quick Share
    // akışıyla devam eder.
    //
    // Receiver proaktif Capabilities GÖNDERMEZ — eski Quick Share peer'ları
    // (Android Samsung, NearDrop, vb.) HekaDropFrame'i decode edemez ve
    // bağlantıyı drop eder. Sender initiates pattern (mDNS-aware), receiver
    // responds on detection.
    let mut active_capabilities: crate::capabilities::ActiveCapabilities =
        crate::capabilities::ActiveCapabilities::legacy();
    // Spec capabilities.md §6: `Capabilities` ikinci kez geldiyse ignore +
    // warn (downgrade/flip-flop attack vector). İlk frame'i işledikten sonra
    // bu flag set; sonraki Capabilities frame'leri active_capabilities'i
    // değiştirmez (PR #114 review, Copilot).
    let mut peer_capabilities_received = false;
    let mut our_capabilities_sent = false;

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
            () = cancel.cancelled() => {
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
                    state.as_ref(),
                );
                ui.notify(UiNotification::Toast {
                    title_key: "notify.app_name",
                    body_key: Some("notify.transfer_cancelled"),
                    body_args: Vec::new(),
                });
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

        // PR #114 (CRITICAL fix for #112): magic-prefix dispatch — sender
        // ext=1 peer'a HekaDropFrame yolluyor (RFC-0003 §3.3 capabilities
        // exchange). Receiver hâlâ ham OfflineFrame::decode yapıyordu →
        // decode error → connection drop → HekaDrop↔HekaDrop transferleri
        // bozuk. Opportunistic dispatch: HekaDropFrame ise handle et,
        // OfflineFrame ise mevcut path.
        match frame::dispatch_frame_body(inner.as_ref()) {
            frame::FrameKind::HekaDrop { inner: ext_bytes } => {
                // PR #114 review (Copilot, capabilities.md §6): magic match
                // sonrası decode/handler hatası **protocol violation** demek
                // (peer/version mismatch bug veya MITM). Spec disconnection +
                // session abort gerektiriyor → log + return Err ile yukarı
                // propagate, `?` ile drop.
                if let Err(e) = handle_hekadrop_frame(
                    ext_bytes,
                    &peer,
                    &mut socket,
                    &mut ctx,
                    &mut active_capabilities,
                    &mut peer_capabilities_received,
                    &mut our_capabilities_sent,
                    &mut assembler,
                    &keys,
                    state.as_ref(),
                    &remote_name_shared,
                    ui.as_ref(),
                )
                .await
                {
                    warn!(
                        "[{}] HekaDropFrame protocol violation; oturum sonlandırılıyor: {:?}",
                        peer, e
                    );
                    cleanup_transfer_state(
                        &peer,
                        &mut assembler,
                        &mut pending_names,
                        &mut pending_texts,
                        state.as_ref(),
                    );
                    let _ = send_disconnection(&mut socket, &mut ctx).await;
                    break;
                }
                continue;
            }
            frame::FrameKind::Offline { body: _ } => {
                // Existing path — `inner` zaten OfflineFrame body'si (magic
                // yok), decode et.
            }
        }

        let offline = OfflineFrame::decode(inner.as_ref()).context("iç OfflineFrame")?;
        let Some(v1) = offline.v1 else {
            continue;
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
                        let body_len_usize = chunk.body.as_ref().map_or(0, |b| b.len());
                        // SECURITY: peer'den gelen `offset` + `body_len` + `total`
                        // alanları unvalidated. `*100` ve `+` operasyonlarını
                        // checked aritmetikle koru; overflow olursa progress
                        // update'ini sessizce atla (DoS koruması — debug build
                        // panic, release wrap, ikisi de istenmiyor).
                        if let Some(percent) = compute_recv_percent(offset, body_len_usize, total) {
                            if let Some(name) = pending_names.get(&id).cloned() {
                                state.set_progress(ProgressState::Receiving {
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
                                handle_text_payload(
                                    &peer,
                                    kind,
                                    &data,
                                    ui.as_ref(),
                                    platform.as_ref(),
                                );
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
                                    ui.as_ref(),
                                    state.as_ref(),
                                    &keys.auth_key,
                                    active_capabilities,
                                )
                                .await?;
                                if outcome == FlowOutcome::Disconnect {
                                    send_disconnection(&mut socket, &mut ctx).await.ok();
                                    cleanup_transfer_state(
                                        &peer,
                                        &mut assembler,
                                        &mut pending_names,
                                        &mut pending_texts,
                                        state.as_ref(),
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
                            finalize_received_payload(
                                &peer,
                                id,
                                &path,
                                total_size,
                                sha256,
                                &remote_name_shared,
                                &mut assembler,
                                state.as_ref(),
                                ui.as_ref(),
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
                        keep_alive: Some(KeepAliveFrame::default()),
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
        state.as_ref(),
    );

    Ok(())
}

/// RFC-0005 §6 — receiver finalize dispatcher. `take_bundle_marker` ile
/// bundle marker varsa extract pipeline çalıştırır (atomic-reject), aksi
/// halde `finalize_received_file`'a delegate eder (mevcut individual file
/// akışı).
///
/// Extract hatası → bundle + staging temizlenmiş olur (`extract_bundle`
/// içinde Drop guard); UI'a `ToastRaw` ile reject mesajı düşer ve hiçbir
/// `History` kaydı eklenmez. Başarı → `History` extract edilen klasör
/// path'i ile push edilir.
#[allow(clippy::too_many_arguments)] // INVARIANT: 9 arg — UI/state/assembler dispatch tek nokta
fn finalize_received_payload(
    peer: &SocketAddr,
    id: i64,
    path: &std::path::Path,
    total_size: i64,
    sha256: [u8; 32],
    remote_name: &str,
    assembler: &mut PayloadAssembler,
    state: &AppState,
    ui: &dyn UiPort,
) {
    if let Some(marker) = assembler.take_bundle_marker(id) {
        // RFC-0005 §6: extract pipeline. Atomic-reject — tüm hata
        // durumlarında staging dir + .bundle Drop'ta silinir.
        match crate::folder::extract::extract_bundle(
            path,
            marker.expected_manifest_sha256_prefix,
            &marker.extract_root_dir,
            &marker.session_id_hex_lower,
        ) {
            Ok(extracted) => {
                info!(
                    "[{}] ✓ folder extract OK: {} ({} entry, {} dosya)",
                    peer,
                    extracted.final_path.display(),
                    extracted.total_entries,
                    extracted.file_count
                );
                // Stats: bundle byte sayısı receiver'a indi (extract sonrası
                // disk üzerindeki dağılım eşit ama metric "alındı" anlamı).
                let keep = state.settings.read().keep_stats;
                let snap_opt = {
                    let mut s = state.stats.write();
                    // INVARIANT (CLAUDE.md I-5): payload finalize'da
                    // total_size ≥ 0 garanti (payload.rs ingest_file negatif
                    // reject); cast güvenli.
                    #[allow(clippy::cast_sign_loss)] // INVARIANT: total_size >= 0 garanti
                    let total_u = total_size as u64;
                    s.record_received(remote_name, total_u);
                    if keep {
                        Some(s.clone())
                    } else {
                        None
                    }
                };
                if let Some(snap) = snap_opt {
                    state.try_save_stats(snap);
                }
                let folder_label = extracted
                    .final_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("klasor")
                    .to_string();
                state.set_progress(ProgressState::Completed {
                    file: folder_label.clone(),
                });
                state.push_history(HistoryItem {
                    file_name: folder_label.clone(),
                    path: extracted.final_path.clone(),
                    size: total_size,
                    device: remote_name.to_string(),
                    when: std::time::SystemTime::now(),
                    sha256_short: hex::encode(sha256).chars().take(16).collect(),
                });
                ui.notify(UiNotification::FileReceived {
                    title_key: "notify.app_name",
                    body_key: "notify.received",
                    body_args: vec![folder_label, format!("{}", extracted.file_count)],
                    path: extracted.final_path,
                });
            }
            Err(e) => {
                warn!(
                    "[{}] folder bundle extract FAIL (atomic-reject): payload_id={} {}",
                    peer, id, e
                );
                state.set_progress(ProgressState::Idle);
                ui.notify(UiNotification::ToastRaw {
                    title: "HekaDrop".to_string(),
                    body: format!("Klasör reddedildi: {e}"),
                });
            }
        }
        return;
    }
    // Mevcut individual file akışı — bundle marker yok.
    finalize_received_file(peer, path, total_size, sha256, remote_name, state, ui);
}

/// `CompletedPayload::File` finalize ortak işleri (stats record, history push,
/// progress update, UI notify). PR refactor: legacy assembler completion
/// path'i ile RFC-0003 chunk-HMAC verify path'i (yine `verify_chunk_tag` ile
/// finalize üretir) aynı helper'ı çağırsın diye çıkarıldı; logic duplikasyonu
/// olmasın.
fn finalize_received_file(
    peer: &SocketAddr,
    path: &std::path::Path,
    total_size: i64,
    sha256: [u8; 32],
    remote_name: &str,
    state: &AppState,
    ui: &dyn UiPort,
) {
    let sha_hex = hex::encode(sha256);
    info!(
        "[{}] ✓ {} alındı — SHA-256: {}",
        peer,
        crate::log_redact::path_basename(path),
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
        let keep = state.settings.read().keep_stats;
        let snap_opt = {
            let mut s = state.stats.write();
            // payload.rs ingest_file aşamasında `total_size < 0` reddediliyor — burada >= 0 garanti.
            #[allow(clippy::cast_sign_loss)]
            let total_size_u = total_size as u64;
            s.record_received(remote_name, total_size_u);
            if keep {
                Some(s.clone())
            } else {
                None
            }
        };
        if let Some(snap) = snap_opt {
            // PR #93 + #109: spawn_blocking + persistence_blocked guard
            // (bozuk stats.json startup'ta backup başarısızsa save'i
            // skip eder — kullanıcı verisini override etmez).
            state.try_save_stats(snap);
        }
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("dosya")
        .to_string();
    state.set_progress(ProgressState::Completed {
        file: file_name.clone(),
    });
    state.push_history(HistoryItem {
        file_name: file_name.clone(),
        path: path.to_path_buf(),
        size: total_size,
        device: remote_name.to_string(),
        when: std::time::SystemTime::now(),
        sha256_short: sha_hex.chars().take(16).collect(),
    });
    info!(
        "[{}] ✓ kaydedildi: {} ({} bayt)",
        peer,
        crate::log_redact::path_basename(path),
        total_size
    );
    ui.notify(UiNotification::FileReceived {
        title_key: "notify.app_name",
        body_key: "notify.received",
        body_args: vec![file_name, human_size(total_size)],
        path: path.to_path_buf(),
    });
}

/// Yarım kalan alıcı state'ini temizler.
///
/// Reject, kullanıcı Cancel, peer Disconnect, I/O hatası veya socket
/// kopması durumlarının hepsinde güvenli biçimde çağrılır; idempotent'tir.
/// Yaptığı işler:
///   * `pending_names` içindeki her `payload_id` için `PayloadAssembler::cancel`
///     çağrılır — yarım yazılmış dosyalar ve açık dosya kulpları temizlenir,
///     disk sızıntısı önlenir.
///   * `pending_texts` ve `pending_names` tamamen boşaltılır.
///   * Progress durumu `Idle` yapılır (UI "alınıyor…" takılı kalmasın).
///
/// Not: Global cancel root'a DOKUNULMAZ (H#1). Paralel koşan diğer handler'ların
/// child token'ları aynı root'tan türediği için burada sıfırlama, bir tarafın
/// tamamlanması esnasında diğer tarafa gelen cancel'i kaybetmeye yol açardı.
/// Per-transfer map temizliği `TransferGuard::drop` ile yapılır.
fn cleanup_transfer_state(
    peer: &SocketAddr,
    assembler: &mut PayloadAssembler,
    pending_names: &mut HashMap<i64, String>,
    pending_texts: &mut HashMap<i64, TextType>,
    state: &AppState,
) {
    let n = drain_pending(assembler, pending_names, pending_texts);
    state.set_progress(ProgressState::Idle);

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

// RFC-0001 §5 Adım 5b: handler call-graph'ında 13 arg vardı; 14. olarak `ui`
// eklendi. Adım 5c'de 15. olarak `state` eklendi (singleton lookup yerine
// inject); helper'lar bir sonraki refactor'da struct olarak gruplanacak.
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
    peer_secret_id_hash: &mut Option<[u8; 6]>,
    ui: &dyn UiPort,
    state: &AppState,
    // RFC-0004 §3.3: resume `.meta` enable + Introduction `ResumeHint` emit
    // için gerekli. `auth_key` → `session_id_i64`, `active_capabilities` →
    // `RESUME_V1` gate.
    auth_key: &[u8],
    active_capabilities: crate::capabilities::ActiveCapabilities,
) -> Result<FlowOutcome> {
    let v1 = frame.v1.as_ref().ok_or_else(|| anyhow!("sharing v1 yok"))?;
    let t = v1.r#type.and_then(|t| sh_v1::FrameType::try_from(t).ok());
    match t {
        Some(sh_v1::FrameType::PairedKeyEncryption) if !*sent_paired_result => {
            // Issue #17: peer'ın secret_id_hash'ini yakala. 6 bayt olmayan
            // değerler (eski / bozuk peer) yok sayılır → legacy fallback.
            if let Some(pke) = v1.paired_key_encryption.as_ref() {
                if let Some(raw) = pke.secret_id_hash.as_ref() {
                    if raw.len() == 6 {
                        let mut h = [0u8; 6];
                        h.copy_from_slice(raw);
                        *peer_secret_id_hash = Some(h);
                    } else {
                        info!(
                            "[{}] peer secret_id_hash beklenen 6 bayt değil ({}) — legacy fallback",
                            peer,
                            raw.len()
                        );
                    }
                }
            }
            // Issue #17 post-hoc muafiyet: Hash-first trust kararı burada
            // doğrulanırsa, `handle` fonksiyonunun gate'inde kaydettiğimiz
            // rate-limit timestamp'ini geri alırız. Böylece hash-verified
            // trusted peer gate'de yakalanan sayaca tabi olmaz, ama
            // peer-controlled string (name/id) spoof'u muafiyet kazandırmaz.
            if let Some(h) = *peer_secret_id_hash {
                if state.settings.read().is_trusted_by_hash(&h) {
                    state.rate_limiter.forget_most_recent(peer.ip());
                    info!(
                        "[{}] trusted hash doğrulandı — rate-limit kaydı geri alındı",
                        peer
                    );
                }
            }
            send_sharing_frame(socket, ctx, &build_paired_key_result()).await?;
            *sent_paired_result = true;
        }
        // PROTO: Explicit no-op (catch-all'a düşmesin diye yazılı): biz
        // `build_paired_key_result()` gönderdik, peer'ın aynısını geri yollayışı
        // protokol gereği — dokümante edilmiş expected frame, action yok. Match
        // arm clippy::match_same_arms `_ => {}`'ye birleştir önerirse anlam
        // kaybı; allow ile koruyoruz.
        #[allow(clippy::match_same_arms)]
        Some(sh_v1::FrameType::PairedKeyResult) => {}
        Some(sh_v1::FrameType::Introduction) => {
            let intro = v1
                .introduction
                .as_ref()
                .ok_or_else(|| anyhow!("introduction yok"))?;
            let file_count = intro.file_metadata.len();
            let text_count = intro.text_metadata.len();

            // SECURITY: `prost` repeated alan cardinality sınırlaması uygulamıyor;
            // saldırgan milyonlarca `file_metadata` göndererek UI dialog'u
            // donduracak kadar Vec allocation + `prompt_accept` summary render
            // maliyeti yaratabilir. Quick Share pratikte tek aktarımda
            // yüzlerce dosya yeterli — 1000 cömert üst sınır.
            if file_count > 1000 || text_count > 64 {
                return Err(HekaError::IntroductionFlood {
                    files: file_count,
                    texts: text_count,
                }
                .into());
            }

            info!(
                "[{}] Introduction: {} dosya, {} metin",
                peer, file_count, text_count
            );

            let mut summaries: Vec<FileSummary> = Vec::new();
            // RFC-0004 §3.3: planned_files'a announced size eklendi —
            // resume `.meta` validate'inde `meta.total_size == introduction.size`
            // invariant'ı için. Sender Introduction'da büyüklüğü bildirir;
            // mismatch → stale meta sil + fresh transfer.
            let mut planned_files: Vec<(i64, std::path::PathBuf, String, i64)> = Vec::new();
            // RFC-0005 §6: bundle marker'ları paralel olarak biriktir; consent
            // accept sonrası `register_bundle_marker` ile assembler'a tanıtılır.
            // Tuple: (payload_id, expected_attachment_hash_prefix, downloads_dir_clone).
            let mut planned_bundles: Vec<(i64, i64, std::path::PathBuf)> = Vec::new();
            // RFC-0005 §6: folder capability aktif mi — Introduction'daki
            // bundle MIME marker'ını ya extract pipeline'a yönlendirir ya da
            // raw `.hekabundle` save fallback'i (capability inactive).
            let folder_active =
                active_capabilities.has(crate::capabilities::features::FOLDER_STREAM_V1);
            for f in &intro.file_metadata {
                let name = f.name.clone().unwrap_or_else(|| "dosya".into());
                let raw_size = f.size.unwrap_or(0);
                let size = match crate::file_size_guard::classify_file_size(raw_size) {
                    crate::file_size_guard::FileSizeGuard::Accept(s) => s,
                    crate::file_size_guard::FileSizeGuard::Clamped => {
                        warn!(
                            "[{}] FileMetadata.size negatif ({}) — 0'a clamp edildi (ad: {})",
                            peer,
                            raw_size,
                            crate::log_redact::path_basename(std::path::Path::new(&name))
                        );
                        0
                    }
                    crate::file_size_guard::FileSizeGuard::Reject => {
                        warn!(
                            "[{}] FileMetadata.size MAX_FILE_BYTES sınırını aştı ({} > {}) — Introduction reddediliyor",
                            peer,
                            raw_size,
                            crate::file_size_guard::MAX_FILE_BYTES
                        );
                        for (_pid, path, _name, _size) in &planned_files {
                            if let Err(e) = std::fs::remove_file(path) {
                                if e.kind() != std::io::ErrorKind::NotFound {
                                    tracing::debug!(
                                        "size-guard cleanup: placeholder silinemedi {}: {}",
                                        crate::log_redact::path_basename(path),
                                        e
                                    );
                                }
                            }
                        }
                        send_sharing_frame(socket, ctx, &build_sharing_cancel()).await?;
                        return Err(HekaError::PayloadSizeAbsurd(raw_size).into());
                    }
                };
                summaries.push(FileSummary {
                    name: name.clone(),
                    size,
                });
                if let Some(pid) = f.payload_id {
                    // RFC-0005 §6 — bundle MIME tespiti. Capability aktif ise
                    // `.bundle` temp path'e route et + bundle marker biriktir.
                    // Capability inactive ise spec §7 receiver-side defensive:
                    // raw `.hekabundle` olarak Downloads'a düşür (mevcut akış,
                    // unique_downloads_path) + warn log.
                    let mime = f.mime_type.as_deref().unwrap_or("");
                    if mime == FOLDER_BUNDLE_MIME && folder_active {
                        // Bundle path: ~/Downloads/.hekadrop-temp-<sid>.bundle.
                        // Session id auth_key'den; aynı session içinde paralel
                        // bundle pratikte yok (sender tek bundle/payload).
                        let downloads_dir = state
                            .settings
                            .read()
                            .resolved_download_dir(|| state.default_download_dir.clone());
                        // INVARIANT (CLAUDE.md I-2): bit-cast — i64 → u64
                        // hex render, no value change.
                        #[allow(clippy::cast_sign_loss)] // INVARIANT: bit-cast for hex rendering
                        let session_hex =
                            format!("{:016x}", crate::resume::session_id_i64(auth_key) as u64);
                        let bundle_path =
                            downloads_dir.join(format!(".hekadrop-temp-{session_hex}.bundle"));
                        // create_dir_all + atomic placeholder reserve (TOCTOU).
                        // Bundle marker'ı `planned_bundles` içine biriktirilir;
                        // `register_bundle_marker` consent accept sonrası
                        // çağrılır ki cancel/reject yolunda gereksiz state
                        // kalmasın.
                        tokio::task::block_in_place(|| -> Result<()> {
                            std::fs::create_dir_all(&downloads_dir).ok();
                            // Placeholder reserve — eski .bundle kalıntısı
                            // varsa temizle (önceki crash artığı).
                            let _ = std::fs::remove_file(&bundle_path);
                            std::fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&bundle_path)
                                .with_context(|| {
                                    format!(
                                        "bundle placeholder rezerve edilemedi: {}",
                                        bundle_path.display()
                                    )
                                })?;
                            Ok(())
                        })?;
                        let attachment_hash = f.attachment_hash.unwrap_or(0);
                        info!(
                            "[{}] folder bundle Introduction: payload_id={}, mime={}, attachment_hash={:#018x}",
                            peer, pid, FOLDER_BUNDLE_MIME, attachment_hash
                        );
                        planned_files.push((pid, bundle_path, name, size));
                        planned_bundles.push((pid, attachment_hash, downloads_dir));
                    } else {
                        if mime == FOLDER_BUNDLE_MIME && !folder_active {
                            // Spec §7 defensive — capability advertise edilmedi
                            // ama sender bundle gönderdi. Raw `.hekabundle`
                            // olarak save (no extraction).
                            warn!(
                                "[{}] folder bundle MIME geldi ama FOLDER_STREAM_V1 negotiate edilmemiş — raw .hekabundle save (spec §7)",
                                peer
                            );
                        }
                        // `unique_downloads_path` `std::fs::create_dir_all` +
                        // `OpenOptions::create_new` (atomic placeholder reserve) gibi
                        // sync I/O yapar; worker thread bloklamamak için
                        // `block_in_place` (multi-thread runtime'da scheduler'ı
                        // bilgilendirir, result inline alınır). PR #93 Gemini review.
                        let target =
                            tokio::task::block_in_place(|| unique_downloads_path(&name, state))?;
                        planned_files.push((pid, target, name, size));
                    }
                }
            }

            let mut planned_texts: Vec<(i64, TextType)> = Vec::new();
            for tm in &intro.text_metadata {
                let kind = TextType::try_from(tm.r#type.unwrap_or(0)).unwrap_or(TextType::Unknown);
                if let Some(pid) = tm.payload_id {
                    planned_texts.push((pid, kind));
                }
            }

            // Karar mantığı (Issue #17):
            //   1) Peer secret_id_hash gönderdiyse → YALNIZ hash eşleşmesi
            //      trust'a yeterlidir. Legacy `(name, id)` fallback bu yolda
            //      devreye alınmaz.
            //   2) Peer hash göndermediyse (pre-v0.6 peer) → legacy
            //      `(name, id)` eşleşmesi (3 sürümlük uyumluluk penceresi).
            //   3) Settings.auto_accept → dialog atla.
            //   4) Aksi halde dialog göster (3 seçenek: reddet/kabul/kabul+güven).
            //
            // SECURITY (PR #35 review — Copilot HIGH, discussion_r3107564927):
            // PR #35'in ilk fix'i `Some(h) => is_trusted_by_hash(h) ||
            // is_trusted_legacy(name, id)` kullanıyordu. Bu OR fallback
            // legacy `(name, id)` spoofing vektörünü geri açmıştı: attacker
            // kurbanın endpoint-id + cihaz adını öğrenir → hash gönderir →
            // legacy kaydı OR ile eşleşir → auto-accept → "opportunistic
            // upgrade" attacker'ın hash'ini kalıcı olarak kayda bağlar.
            // Bundan sonra legacy fallback kaldırılsa bile attacker sessiz
            // bypass ile trusted kalır.
            //
            // Legacy kullanıcı migration UX: v0.5 → v0.6 geçişinde legitimate
            // cihazın ilk hash-gönderili bağlantısında dialog ONE-TIME çıkar
            // (çünkü hash henüz kayıtta yok). Kullanıcı Accept / Accept+Trust
            // dediğinde aşağıdaki opportunistic upgrade hash'i legacy kayda
            // bağlar; sonraki bağlantılar hash-first trusted, dialog yok.
            // Bu migration-dialog-cost spoofing engelinin doğru bedelidir.
            let trusted = {
                let s = state.settings.read();
                match peer_secret_id_hash {
                    Some(h) => s.is_trusted_by_hash(h),
                    None => s.is_trusted_legacy(remote_name, remote_id),
                }
            };

            // TODO(ux): peer hash gönderdiği halde is_trusted_by_hash false ama
            // is_trusted_legacy true ise — bu "v0.5 legacy kullanıcı ilk v0.6
            // bağlantısı" senaryosudur. Dialog prompt'unu customize etmek
            // kullanıcıya one-time dialog'un nedenini açıklar
            // ("Önceki güvenilir cihazın yeni kimliği doğrulanıyor…").
            // prompt_accept() imzası şu an custom prompt kabul etmediği için
            // (macOS/Windows/Linux 3 ayrı blocking fn) bu polish atlandı.

            let auto_accept = state.settings.read().auto_accept;

            // Dalga 3 UX: Peer hash göndermiş olduğu halde hash kayıtta yoksa,
            // `(name, id)` legacy kaydı varsa — bu "v0.5 → v0.6 migration"
            // senaryosudur. Dialog açılmadan önce kullanıcıya nedenini
            // açıklayan bir bildirim gönder; aksi halde tanıdık cihaz için
            // birden dialog görünce "güveni zedelenmiş mi?" tereddüdü doğar.
            let migration_hint = peer_secret_id_hash.is_some() && !trusted && {
                let s = state.settings.read();
                s.is_trusted_legacy(remote_name, remote_id)
            };

            let decision = if trusted {
                info!("[{}] trusted cihaz → otomatik kabul", peer);
                // Sliding-window TTL: aktif kullanım varsa timestamp'i yenile.
                if let Some(h) = peer_secret_id_hash {
                    let snap = {
                        let mut s = state.settings.write();
                        s.touch_trusted_by_hash(h);
                        s.clone()
                    };
                    // PR #93 + #109: try_save_settings = spawn_blocking +
                    // persistence_blocked guard (bozuk config korunsun).
                    state.try_save_settings(snap);
                }
                AcceptDecision::Accept
            } else if auto_accept {
                info!("[{}] settings.auto_accept=true → otomatik kabul", peer);
                AcceptDecision::Accept
            } else {
                if migration_hint {
                    info!(
                        "[{}] legacy → hash migration dialog'u gösteriliyor: {}",
                        peer, remote_name
                    );
                    ui.notify(UiNotification::TrustMigrationHint {
                        device: remote_name.to_string(),
                        pin: pin_code.to_string(),
                    });
                }
                ui.prompt_accept(remote_name, pin_code, &summaries, text_count)
                    .await
            };

            let ok = !matches!(decision, AcceptDecision::Reject);
            *accepted_flag = ok;

            // Opportunistic legacy → hash upgrade.
            //
            // SECURITY (Copilot review #34 HIGH): **yalnızca** kullanıcı
            // kabul ettiyse çalışır. Önceki kod dialog öncesinde, kararın
            // farkında olmadan upgrade yapıyordu — attacker bağlanır, kullanıcı
            // reddeder, ama attacker'ın hash'i legacy kayda bağlanmış olurdu;
            // bir sonraki bağlantısında hash-first kararla sessizce auto-accept
            // edilirdi (dialog bypass).
            //
            // Tasarım (design 017 §5.2): "user zaten 'bu cihazı güven' demişti"
            // — yani legacy kayıt varsa ve kullanıcı ŞU ANDAKİ bağlantıyı
            // reddetmiyorsa hash'i işle. `AcceptAndTrust` branch'i zaten
            // `add_trusted_with_hash` ile upgrade eder (legacy match → hash
            // doldurulur); burada sadece düz `Accept` + legacy varsa enrich
            // ederiz. Reject yolunda hiçbir zaman çalışmaz.
            if matches!(decision, AcceptDecision::Accept) {
                if let Some(h) = peer_secret_id_hash {
                    let needs_upgrade = {
                        let s = state.settings.read();
                        s.is_trusted_legacy(remote_name, remote_id) && !s.is_trusted_by_hash(h)
                    };
                    if needs_upgrade {
                        let snap = {
                            let mut s = state.settings.write();
                            s.add_trusted_with_hash(remote_name, remote_id, *h);
                            s.clone()
                        };
                        state.try_save_settings(snap);
                        info!(
                            "[{}] legacy trust kaydı secret_id_hash ile yükseltildi: {}",
                            peer, remote_name
                        );
                    }
                }
            }

            if matches!(decision, AcceptDecision::AcceptAndTrust) {
                let snap = {
                    let mut s = state.settings.write();
                    if let Some(h) = peer_secret_id_hash {
                        s.add_trusted_with_hash(remote_name, remote_id, *h);
                    } else {
                        // Peer hash göndermedi — legacy kayıt yazılır.
                        // Üç sürüm sonra (v0.7) bu yol kaldırılacak; o zamana
                        // kadar kullanıcı trust seçtiği halde spec'e uymayan
                        // peer'lar çalışmaya devam etsin.
                        info!(
                            "[{}] peer secret_id_hash göndermedi — legacy trust kaydı yazıldı",
                            peer
                        );
                        s.add_trusted(remote_name, remote_id);
                    }
                    s.clone()
                };
                state.try_save_settings(snap);
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
                ui.notify(UiNotification::ToastRaw {
                    title: "HekaDrop".to_string(),
                    body: format!("{remote_name} artık güvenilir cihaz"),
                });
            }

            if ok {
                // RFC-0004 §3.3: capability gate. RESUME_V1 aktif olmadıkça
                // hiçbir `.meta` dosyası okunmaz/yazılmaz/emit edilmez —
                // mevcut path tamamen değişmez. Şu an `ALL_SUPPORTED` `RESUME_V1`
                // içermediği için pratikte unreachable; PR-F'de feature
                // bit aktive olunca devreye girer.
                let resume_active =
                    active_capabilities.has(crate::capabilities::features::RESUME_V1);
                let session_id = if resume_active {
                    Some(crate::resume::session_id_i64(auth_key))
                } else {
                    None
                };
                // PR #133 medium: `partial_dir()` her dosya için ayrı çağrılıyordu
                // (`resolve_resume_path` + `handle_resume_for_file`). Loop ÖNCESİ
                // tek sefer hesapla — N dosya için 2N→1 dizin ensure I/O. None →
                // HOME yok / mkdir başarısız → resume tamamen skip (fresh transfer).
                let cached_partial_dir: Option<std::path::PathBuf> = if session_id.is_some() {
                    crate::resume::partial_dir().ok()
                } else {
                    None
                };
                for (pid, fresh_path, display_name, announced_size) in planned_files {
                    // PR-G: RESUME_V1 + meta valid + meta.dest_path mevcut →
                    // fresh placeholder'ı sil + meta.dest_path'i register et
                    // (mevcut `.part` üstüne devam). Aksi halde fresh_path.
                    let actual_path = if let (Some(sid), Some(dir)) =
                        (session_id, cached_partial_dir.as_deref())
                    {
                        match resolve_resume_path(dir, sid, pid, &display_name, announced_size) {
                            Some(resume_path) => {
                                // Fresh placeholder boş — sil, resume path'e geç.
                                if let Err(e) = std::fs::remove_file(&fresh_path) {
                                    if e.kind() != std::io::ErrorKind::NotFound {
                                        tracing::debug!(
                                            "[{}] resume swap: fresh placeholder silinemedi {}: {}",
                                            peer,
                                            crate::log_redact::path_basename(&fresh_path),
                                            e
                                        );
                                    }
                                }
                                tracing::info!(
                                    "[{}] resume aktif: payload_id={} → mevcut .part'a devam ({})",
                                    peer,
                                    pid,
                                    crate::log_redact::path_basename(&resume_path)
                                );
                                resume_path
                            }
                            None => fresh_path,
                        }
                    } else {
                        fresh_path
                    };

                    assembler
                        .register_file_destination(pid, actual_path)
                        .context("dosya hedefi kaydı")?;
                    pending_names.insert(pid, display_name.clone());

                    // RFC-0005 §6: bundle marker register (varsa). Bu pid
                    // `planned_bundles`'da ise extract pipeline'ın ihtiyacı
                    // olan attachment_hash + extract dir + session hex'i
                    // assembler'a tanıt. CompletedPayload::File döndüğünde
                    // caller `take_bundle_marker(pid)` ile çekecek.
                    if let Some((_, attach_hash, dl_dir)) =
                        planned_bundles.iter().find(|(b_pid, _, _)| *b_pid == pid)
                    {
                        // INVARIANT (CLAUDE.md I-2): bit-cast — i64 → u64 hex
                        // render, no value change.
                        #[allow(clippy::cast_sign_loss)] // INVARIANT: bit-cast for hex rendering
                        let session_hex =
                            format!("{:016x}", crate::resume::session_id_i64(auth_key) as u64);
                        assembler.register_bundle_marker(
                            pid,
                            crate::payload::BundleMarker {
                                expected_manifest_sha256_prefix: *attach_hash,
                                extract_root_dir: dl_dir.clone(),
                                session_id_hex_lower: session_hex,
                            },
                        );
                    }

                    // RFC-0004 §3.3 — Introduction sonrası `.meta` lookup
                    // + (matching ise) `ResumeHint` emit. Hata yutulur:
                    // resume best-effort, fresh transfer her zaman OK.
                    if let (Some(sid), Some(dir)) = (session_id, cached_partial_dir.as_deref()) {
                        if let Err(e) = handle_resume_for_file(
                            socket,
                            ctx,
                            assembler,
                            dir,
                            sid,
                            pid,
                            &display_name,
                            announced_size,
                            remote_id,
                        )
                        .await
                        {
                            tracing::debug!(
                                "[{}] resume handler skip (payload_id={}): {}",
                                peer,
                                pid,
                                e
                            );
                        }
                    }
                }
                for (pid, kind) in planned_texts {
                    pending_texts.insert(pid, kind);
                }
                send_sharing_frame(socket, ctx, &build_consent_accept()).await?;
                info!("[{}] ✓ kullanıcı kabul etti", peer);
            } else {
                // Reject: `unique_downloads_path` her `planned_files` için
                // `create_new(true)` ile 0-bayt placeholder rezerve etmişti.
                // Hiçbirini PayloadAssembler'a kaydetmediğimiz için normal
                // cleanup yolu bunları bilmiyor — burada elle siliyoruz,
                // aksi halde indirme klasöründe sahipsiz boş dosyalar birikir
                // (review-18 MED).
                for (_pid, path, _name, _size) in &planned_files {
                    if let Err(e) = std::fs::remove_file(path) {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            tracing::debug!(
                                "reject cleanup: placeholder silinemedi {}: {}",
                                crate::log_redact::path_basename(path),
                                e
                            );
                        }
                    }
                }
                send_sharing_frame(socket, ctx, &build_consent_reject()).await?;
                info!("[{}] ✗ kullanıcı reddetti", peer);
                ui.notify(UiNotification::ToastRaw {
                    title: "HekaDrop".to_string(),
                    body: format!("{remote_name}: aktarım reddedildi"),
                });
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

fn handle_text_payload(
    peer: &SocketAddr,
    kind: TextType,
    data: &[u8],
    ui: &dyn UiPort,
    platform: &dyn PlatformOps,
) {
    let text = if let Ok(s) = std::str::from_utf8(data) {
        s.trim().to_string()
    } else {
        warn!("[{}] UTF-8 olmayan metin payload", peer);
        return;
    };
    if kind == TextType::Url {
        if is_safe_url_scheme(&text) {
            platform.open_url(&text);
            // PRIVACY: Log dosyasına yalnız şema + host düşer; path + query
            // (token içerebilir) redact. UI bildirimi kullanıcının kendi
            // ekranında olduğu için tam preview'la gösterilir.
            info!(
                "[{}] URL açıldı: {}",
                peer,
                crate::log_redact::url_scheme_host(&text)
            );
            ui.notify(UiNotification::Toast {
                title_key: "notify.app_name",
                body_key: Some("notify.url_opened"),
                body_args: vec![preview(&text, 80)],
            });
        } else {
            // SECURITY: http/https dışı şemalar (javascript:, file://, smb://
            // vb.) exfiltration / RCE / NTLM leak riskidir. Otomatik
            // açılmaz; metin clipboard'a kopyalanır ve kullanıcıya bildirilir.
            // PRIVACY: Güvensiz URL'nin şema + host'u debug için yeterli;
            // tam string (javascript: payload vb.) log'a düşmez.
            warn!(
                "[{}] güvensiz şemalı URL reddedildi (yalnız http/https açılır): {}",
                peer,
                crate::log_redact::url_scheme_host(&text)
            );
            platform.copy_to_clipboard(&text);
            ui.notify(UiNotification::Toast {
                title_key: "notify.app_name",
                body_key: Some("notify.text_clipboard"),
                body_args: vec![preview(&text, 80)],
            });
        }
    } else {
        platform.copy_to_clipboard(&text);
        info!(
            "[{}] metin panoya kopyalandı ({} karakter)",
            peer,
            text.len()
        );
        ui.notify(UiNotification::Toast {
            title_key: "notify.app_name",
            body_key: Some("notify.text_clipboard"),
            body_args: vec![preview(&text, 80)],
        });
    }
}

fn preview(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}…")
    }
}

pub(crate) async fn send_disconnection(socket: &mut TcpStream, ctx: &mut SecureCtx) -> Result<()> {
    let f = OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::Disconnection as i32),
            disconnection: Some(DisconnectionFrame::default()),
            ..Default::default()
        }),
    };
    let enc = ctx.encrypt(&f.encode_to_vec())?;
    frame::write_frame(socket, &enc).await?;
    Ok(())
}

fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    // HUMAN: log gösterimi — TB üstü dosyada mantissa hassasiyet kaybı tolere edilir.
    #[allow(clippy::cast_precision_loss)]
    let mut n = bytes as f64;
    let mut i = 0;
    while n >= 1024.0 && i < UNITS.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{:.1} {}", n, UNITS[i])
    }
}

/// PR-G — Introduction handler'ı `unique_downloads_path`'le fresh placeholder
/// rezerve ettikten sonra bu fonksiyonu çağırır. Eğer geçerli bir resume
/// `.meta` varsa + `meta.dest_path` mevcut + dosya boyutu `received_bytes`
/// ile eşleşiyorsa **mevcut `.part` path'i** döner; caller fresh placeholder'ı
/// silip bu path'i register eder. Aksi halde `None` (fresh transfer).
///
/// Validate adımları (RFC §5'teki MUST'larla birebir):
/// - `.meta` load OK + `validate()` OK
/// - `meta.file_name == announced display_name`
/// - `meta.total_size == announced_total_size`
/// - `meta.updated_at` TTL içinde
/// - `meta.dest_path` non-empty + `Path::exists` + `metadata.len() ==
///   meta.received_bytes` (disk doğrulaması)
///
/// `dir` caller-cached `partial_dir()` — Introduction loop ÖNCESİ tek sefer
/// hesaplanıp tüm dosyalar için reuse edilir (PR #133 medium follow-up).
fn resolve_resume_path(
    dir: &std::path::Path,
    session_id: i64,
    payload_id: i64,
    announced_display_name: &str,
    announced_total_size: i64,
) -> Option<std::path::PathBuf> {
    let meta = crate::resume::PartialMeta::load(dir, session_id, payload_id)
        .ok()
        .flatten()?;
    if meta.dest_path.is_empty() {
        return None;
    }
    if meta.file_name != announced_display_name {
        return None;
    }
    if meta.total_size != announced_total_size {
        return None;
    }
    let age_days = (chrono::Utc::now() - meta.updated_at).num_days();
    if age_days > crate::resume::RESUME_TTL_DAYS {
        return None;
    }
    let path = std::path::PathBuf::from(&meta.dest_path);
    let md = std::fs::metadata(&path).ok()?;
    if !md.is_file() {
        return None;
    }
    // SECURITY: untrusted-disk size — `meta.received_bytes` ile eşleşmesi
    // resume offset semantiğinin disk gerçeğine oturduğunu garanti eder.
    // `as u64` bit-cast (u64 rendering); validate() received_bytes >= 0
    // garantilediği için sign loss yok.
    #[allow(clippy::cast_sign_loss)] // INVARIANT: validate() guards received_bytes >= 0
    let expected = meta.received_bytes as u64;
    if md.len() != expected {
        return None;
    }
    Some(path)
}

/// RFC-0004 §3.3 + §5 — Introduction sonrası bir dosya için resume
/// orchestration:
///
/// 1. `.meta` lookup (varsa).
/// 2. Receiver MUST validate (RFC §5):
///    - `meta.total_size == announced_total_size` (mismatch → stale, sil + fresh)
///    - `meta.file_name == announced_file_name` (sanitize edilmiş hâli)
///    - `meta.updated_at` TTL içinde (yoksa → sil + fresh)
///    - `meta.received_bytes <= meta.total_size` (`PartialMeta::validate`'de zaten)
///    - `meta.chunk_size == CHUNK_SIZE` (`PartialMeta::validate`'de zaten)
/// 3. Validate ok → `partial_hash_streaming` recompute (defense-in-depth) +
///    `ResumeHint` envelope encrypt + write.
/// 4. Validate fail → `.meta` + (varsa) `.part` sil; fresh transfer (no emit).
///
/// Her durumda `assembler.enable_resume(...)` çağrılır — devam eden transfer
/// kendi checkpoint döngüsünü kursun (fresh meta yazsın). Hata durumunda
/// `.ok()` ile yutulur (resume best-effort).
///
/// Bu PR (PR-C) kapsamında sadece **emit** tarafı; sender bu hint'i consume
/// edecek (PR-D), receiver `.part` üstüne devam edecek (PR-E).
#[allow(clippy::too_many_arguments)]
async fn handle_resume_for_file(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    assembler: &mut PayloadAssembler,
    dir: &std::path::Path,
    session_id: i64,
    payload_id: i64,
    file_name: &str,
    announced_total_size: i64,
    peer_endpoint_id: &str,
) -> Result<()> {
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;
    use hekadrop_proto::hekadrop_ext::ResumeHint;

    // PR #133 medium: `dir` caller-cached `partial_dir()`. Introduction loop'u
    // tek sefer hesaplar, N dosya için reuse — N×`partial_dir()` mkdir I/O
    // bedeli elimine.

    // `.meta` lookup. NotFound → fresh; load Err → silently skip.
    // PR-G: meta validate sonucuna göre `enable_resume_with_offset` ya da
    // `enable_resume` (fresh) çağrılır — resume aktivasyonu meta sonrasına
    // ertelendi ki `received_bytes` doğru injected olsun.
    let maybe_meta = match crate::resume::PartialMeta::load(dir, session_id, payload_id) {
        Ok(opt) => opt,
        Err(e) => {
            tracing::debug!(
                "resume meta load skip (payload_id={}): {} — fresh transfer",
                payload_id,
                e
            );
            // Fresh enable — `.meta` yazsın ki sonraki kesintide resume
            // şansı doğsun.
            let _ = assembler.enable_resume(
                payload_id,
                session_id,
                peer_endpoint_id.to_string(),
                file_name.to_string(),
            );
            return Ok(());
        }
    };
    let Some(meta) = maybe_meta else {
        // Eşleşen meta yok → fresh enable + ResumeHint emit etme.
        let _ = assembler.enable_resume(
            payload_id,
            session_id,
            peer_endpoint_id.to_string(),
            file_name.to_string(),
        );
        return Ok(());
    };

    // 3. Receiver MUST invariant validate (RFC §5).
    let now = chrono::Utc::now();
    let age_days = (now - meta.updated_at).num_days();
    let stale = age_days > crate::resume::RESUME_TTL_DAYS
        || meta.total_size != announced_total_size
        || meta.file_name != file_name;
    if stale {
        tracing::info!(
            "resume meta stale (payload_id={}): age_days={}, total={}/{}, name={}/{} — sil + fresh",
            payload_id,
            age_days,
            meta.total_size,
            announced_total_size,
            meta.file_name,
            file_name
        );
        let path = dir.join(crate::resume::meta_filename(session_id, payload_id));
        let _ = std::fs::remove_file(&path);
        // Fresh enable — sonraki kesintide yeni `.meta` yazılır.
        let _ = assembler.enable_resume(
            payload_id,
            session_id,
            peer_endpoint_id.to_string(),
            file_name.to_string(),
        );
        return Ok(());
    }

    // 4. Meta valid + RESUME_V1 aktif → resume offset ile enable et.
    //    PR-G: `enable_resume_with_offset` `received_bytes` + chunk_index +
    //    `last_chunk_tag_b64` inject eder; ingest_file ilk chunk'ta `.part`'ı
    //    `truncate(false)` + `seek(received_bytes)` ile açar, hasher önceki
    //    bytes ile feed edilir. `next_chunk_index = received_bytes /
    //    chunk_size` — `validate()` chunk_size == CHUNK_SIZE garantili.
    let chunk_size_i64 = i64::from(meta.chunk_size);
    let next_chunk_idx = if chunk_size_i64 == 0 {
        0
    } else {
        meta.received_bytes / chunk_size_i64
    };
    if let Err(e) = assembler.enable_resume_with_offset(
        payload_id,
        session_id,
        peer_endpoint_id.to_string(),
        file_name.to_string(),
        meta.received_bytes,
        next_chunk_idx,
        meta.chunk_hmac_chain_b64.clone(),
    ) {
        tracing::debug!(
            "resume enable_with_offset failed (payload_id={}, offset={}): {} — fresh devam",
            payload_id,
            meta.received_bytes,
            e
        );
        // Fresh fallback.
        let _ = assembler.enable_resume(
            payload_id,
            session_id,
            peer_endpoint_id.to_string(),
            file_name.to_string(),
        );
        return Ok(());
    }

    // 5. partial_hash recompute (defense-in-depth — disk corruption /
    //    concurrent edit). PR-G: `meta.dest_path` mevcut → gerçek hash
    //    hesaplanır. Hash hesaplanamazsa (path empty / yok / kısa) hint
    //    yine emit edilir ama `partial_hash = []` (sender boşa REJECT döner;
    //    receiver fresh restart'a düşer — best-effort).
    let last_tag_bytes = BASE64_STD
        .decode(&meta.chunk_hmac_chain_b64)
        .unwrap_or_default();

    let partial_hash_bytes: Vec<u8> = if meta.dest_path.is_empty() {
        Vec::new()
    } else {
        // SECURITY: receiver tarafı kendi diskindeki `.part`'ı doğruluyor —
        // `meta.received_bytes` validate'lı. `as u64` bit-cast (validate
        // received_bytes >= 0 garantili).
        #[allow(clippy::cast_sign_loss)] // INVARIANT: validate() guards received_bytes >= 0
        let off_u = meta.received_bytes as u64;
        let dest_path = std::path::Path::new(&meta.dest_path);
        match crate::resume::partial_hash_streaming(dest_path, off_u) {
            Ok(h) => h.to_vec(),
            Err(e) => {
                tracing::debug!(
                    "resume partial_hash compute failed (payload_id={}, path={}): {} — fresh fallback",
                    payload_id,
                    crate::log_redact::path_basename(dest_path),
                    e
                );
                Vec::new()
            }
        }
    };

    let hint = ResumeHint {
        session_id,
        payload_id,
        offset: meta.received_bytes,
        partial_hash: partial_hash_bytes.into(),
        capabilities_version: crate::capabilities::CAPABILITIES_VERSION,
        last_chunk_tag: last_tag_bytes.into(),
    };

    let frame = crate::capabilities::build_resume_hint_frame(hint);
    let pb = frame.encode_to_vec();
    let wrapped = crate::frame::wrap_hekadrop_frame(&pb);
    let enc = ctx.encrypt(&wrapped).context("ResumeHint encrypt")?;
    crate::frame::write_frame(socket, &enc)
        .await
        .context("ResumeHint write")?;
    tracing::info!(
        "resume hint emitted (payload_id={}, offset={})",
        payload_id,
        meta.received_bytes
    );
    Ok(())
}

/// `HekaDrop` extension frame'i parse + handle eder. Magic-prefix dispatch
/// (`frame::dispatch_frame_body`) sonrası caller bu helper'ı çağırır.
///
/// Davranış:
/// - `Capabilities` → peer'ın feature set'i ile bizim `ALL_SUPPORTED`'i
///   negotiate et, `active_capabilities`'i set et. **İlk Capabilities
///   alındığında** bizim Capabilities'imizi peer'a yolla (sender initiate
///   pattern — receiver responds, no blind send to legacy peers).
/// - `ChunkIntegrity` → şu an no-op + log (full chunk-HMAC verify pipeline
///   v0.8 sonraki PR'ı; bu PR critical fix kapsamı).
/// - Bilinmeyen `Payload` varyantı → log + skip (forward-compat).
///
/// Hata döner: socket write, ctx.encrypt, prost decode failure'ları.
#[allow(clippy::too_many_arguments)]
async fn handle_hekadrop_frame(
    bytes: &[u8],
    peer: &SocketAddr,
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    active_capabilities: &mut crate::capabilities::ActiveCapabilities,
    peer_capabilities_received: &mut bool,
    our_capabilities_sent: &mut bool,
    assembler: &mut PayloadAssembler,
    keys: &ukey2::DerivedKeys,
    state: &AppState,
    remote_name: &str,
    ui: &dyn UiPort,
) -> Result<()> {
    use hekadrop_proto::hekadrop_ext::{heka_drop_frame::Payload, HekaDropFrame};
    use tracing::debug;

    let frame = HekaDropFrame::decode(bytes)
        .with_context(|| format!("[{peer}] HekaDropFrame protobuf decode"))?;
    let Some(payload) = frame.payload else {
        debug!("[{peer}] HekaDropFrame.payload boş — skip (forward-compat)");
        return Ok(());
    };

    match payload {
        Payload::Capabilities(peer_caps) => {
            // Spec capabilities.md §6: aynı oturumda ikinci Capabilities frame
            // ignore + warn. Downgrade/flip-flop attack vector — peer
            // ilk frame'de tüm özellikleri reklam eder, sonra azaltıp aktif
            // chunk-HMAC vb.'yi kapatabilir. İlk frame karara bağlanır.
            if *peer_capabilities_received {
                warn!(
                    "[{}] ikinci Capabilities frame yok sayıldı (spec §6 — downgrade engelleme)",
                    peer
                );
                return Ok(());
            }

            let our_features = crate::capabilities::features::ALL_SUPPORTED;
            *active_capabilities = crate::capabilities::ActiveCapabilities::negotiate(
                our_features,
                peer_caps.features,
            );
            *peer_capabilities_received = true;
            info!(
                "[{}] active capabilities: 0x{:04x} (chunk_hmac={}, resume={}, folder={})",
                peer,
                active_capabilities.raw(),
                active_capabilities.has(crate::capabilities::features::CHUNK_HMAC_V1),
                active_capabilities.has(crate::capabilities::features::RESUME_V1),
                active_capabilities.has(crate::capabilities::features::FOLDER_STREAM_V1),
            );

            // RFC-0003 §4.1: capability aktif ise chunk-HMAC anahtarını
            // assembler'a kur. PayloadAssembler artık her FILE chunk'ını
            // pending buffer'a alır, ChunkIntegrity verify olduktan sonra
            // diske yazar (storage corruption early-abort).
            if active_capabilities.has(crate::capabilities::features::CHUNK_HMAC_V1) {
                let key = crate::chunk_hmac::derive_chunk_hmac_key(&keys.next_secret);
                assembler.set_chunk_hmac_key(key);
                info!(
                    "[{}] chunk-HMAC anahtarı türetildi + assembler'a kuruldu (RFC-0003 §4.1)",
                    peer
                );
            }

            if !*our_capabilities_sent {
                let our = crate::capabilities::build_capabilities_frame(
                    crate::capabilities::build_self_capabilities(),
                );
                let pb = our.encode_to_vec();
                let wrapped = frame::wrap_hekadrop_frame(&pb);
                let enc = ctx
                    .encrypt(&wrapped)
                    .with_context(|| format!("[{peer}] our Capabilities encrypt"))?;
                frame::write_frame(socket, &enc)
                    .await
                    .with_context(|| format!("[{peer}] our Capabilities write"))?;
                *our_capabilities_sent = true;
                info!("[{}] receiver Capabilities geri yollandı", peer);
            }
            Ok(())
        }
        Payload::ChunkTag(ci) => {
            // RFC-0003 §5: ChunkIntegrity verify pipeline. Capability gate
            // kapalıysa peer protocol violation yapıyor (spec §9 son satır:
            // "Sender sends tag but receiver lacks capability") — abort +
            // disconnect (caller `?` ile yukarı propagate edip session sonu
            // tetikler).
            if !active_capabilities.has(crate::capabilities::features::CHUNK_HMAC_V1) {
                return Err(HekaError::ProtocolState(format!(
                    "[{peer}] ChunkIntegrity geldi ama CHUNK_HMAC_V1 capability negotiate edilmemiş (spec §9)"
                )).into());
            }
            debug!(
                "[{}] ChunkTag verify: payload_id={}, chunk_index={}, offset={}, body_len={}",
                peer, ci.payload_id, ci.chunk_index, ci.offset, ci.body_len
            );
            // PRIVACY (spec §10): ChunkIntegrity.tag içeriği log'a düşmez —
            // sadece kategori metadata. Hata durumunda da mesajda tag yok.
            match assembler.verify_chunk_tag(&ci).await {
                Ok(None) => Ok(()),
                Ok(Some(crate::payload::CompletedPayload::File {
                    id,
                    path,
                    total_size,
                    sha256,
                })) => {
                    debug!("[{}] chunk-HMAC verify path: dosya finalize id={id}", peer);
                    finalize_received_payload(
                        peer,
                        id,
                        &path,
                        total_size,
                        sha256,
                        remote_name,
                        assembler,
                        state,
                        ui,
                    );
                    Ok(())
                }
                Ok(Some(other)) => {
                    // Bytes payload'lar verify pipeline'ından geçmez (sender
                    // chunk-HMAC sadece FILE chunk'ları için emit eder).
                    // Defensive: forward-compat için error.
                    Err(anyhow!(
                        "[{peer}] verify_chunk_tag beklenmedik CompletedPayload varyantı: {other:?}"
                    ))
                }
                Err(e) => {
                    // Spec §9: cleanup_transfer_state + Disconnection.
                    // Caller (steady loop) `?` ile yakalar, log + cleanup
                    // ardından send_disconnection. .part dosyası kapalı
                    // FileSink artakaldıysa sonraki cleanup_transfer_state
                    // çağrısı yarım dosyayı kanca'dan düşürür.
                    warn!(
                        "[{}] chunk-HMAC verify FAIL — protokol ihlali / corruption (payload_id={}, chunk_index={}): {}",
                        peer, ci.payload_id, ci.chunk_index, e
                    );
                    // Failure path'inde pending_chunk hâlâ FileSink içinde
                    // olabilir (verify_chunk_tag erken return etti). Sink'i
                    // cancel et ki .part diskten silinsin (RFC-0003 §9 row 3).
                    assembler.cancel(ci.payload_id);
                    Err(e)
                }
            }
        }
        // Forward-compat stub'ları RFC-bazında ayrı arm'lar — her birinin
        // tam implementasyonu ayrı PR serisinde gelecek (RFC-0004 PR-B+,
        // RFC-0005). Şimdilik sessizce drop, ama ayrı log satırlarıyla
        // dispatch path'i debugging'de net görünür.
        Payload::ResumeHint(_hint) => {
            debug!("[{}] ResumeHint frame received (RFC-0004 stub)", peer);
            Ok(())
        }
        Payload::ResumeReject(_reject) => {
            debug!("[{}] ResumeReject frame received (RFC-0004 stub)", peer);
            Ok(())
        }
        Payload::FolderMft(_mft) => {
            debug!("[{}] FolderMft frame received (RFC-0005 stub)", peer);
            Ok(())
        }
    }
}

fn unique_downloads_path(name: &str, state: &AppState) -> Result<PathBuf> {
    // SECURITY/TOCTOU: Önceki sürüm `Path::exists()` + sonra `File::create`
    // kullanıyordu. İki paralel alıcı (server.rs `MAX_CONCURRENT_CONNECTIONS=32`)
    // aynı ismi aynı anda "mevcut değil" görüp aynı `candidate`'i seçebilir;
    // sonraki `File::create` ikinci alıcının verisini `O_TRUNC` ile silerek
    // birincinin yazdığını yok ederdi.
    // Çözüm: `OpenOptions::create_new(true)` ile **atomic** reserve — işletim
    // sistemi düzeyinde `O_EXCL` (POSIX) / `CREATE_NEW` (Windows). İlk sahibin
    // placeholder'ı kazanır; ikincisi `AlreadyExists` alıp sonraki isme geçer.
    // Placeholder sıfır bayt olarak diskte kalır; `PayloadAssembler::ingest_file`
    // onu `OpenOptions::write(true).truncate(true)` ile yeniden açarak gerçek
    // veriyle doldurur (aynı path, aynı inode).
    fn try_reserve(candidate: &std::path::Path) -> std::io::Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(candidate)
            .map(|_| ())
    }

    let base = state
        .settings
        .read()
        .resolved_download_dir(|| state.default_download_dir.clone());
    std::fs::create_dir_all(&base).ok();

    // SECURITY: Uzak cihazdan gelen dosya adı saldırgan kontrolünde; doğrudan
    // `base.join(name)` path traversal'a açıktır — sanitize ile yalnız
    // basename kalır, `..`/`/`/`\`/NUL/control char silinir, Windows
    // reserved adları (CON, PRN…) yeniden adlandırılır.
    let safe = sanitize_received_name(name);

    let candidate = base.join(&safe);
    match try_reserve(&candidate) {
        Ok(()) => return Ok(candidate),
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(anyhow!("dosya rezerve edilemedi: {e}"));
        }
        Err(_) => {}
    }

    let (stem, ext) = split_name(&safe);
    let mut n = 1;
    loop {
        let filename = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        let next = base.join(filename);
        match try_reserve(&next) {
            Ok(()) => return Ok(next),
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(anyhow!("dosya rezerve edilemedi: {e}"));
            }
            Err(_) => {}
        }
        n += 1;
        if n > 10_000 {
            return Err(HekaError::FileNameExhausted.into());
        }
    }
}

/// Uzak cihazdan gelen dosya adını güvenli hale getirir.
///
/// **Neden gerekli:** `FileMetadata.name` attacker-controlled. Sanitize
/// edilmediğinde `../../../.bashrc` veya `C:\Windows\System32\drivers\...`
/// gibi path traversal saldırıları `File::create` ile silent overwrite'a
/// çevrilir (özellikle `auto_accept=true` veya trusted device yolunda).
///
/// Kurallar:
/// 1. Path separator'a kadar tüm prefix atılır (yalnız basename kalır) —
///    hem `/` hem `\` ele alınır (Windows'ta `\` da separator).
/// 2. `.` ve `..` tek başına ya da başta/sonda olduğunda geçersizdir; böyle
///    adlar `dosya`'ya düşer.
/// 3. NUL + control (`< 0x20`, `0x7F`) **+ Windows yasaklı karakterler**
///    (`< > : " / \ | ? *`) filtrelenir. `:` özellikle NTFS Alternate Data
///    Stream (ADS) vektörüdür (`ok.txt:evil`).
/// 4. Trailing dot/space Windows tarafından yok sayılır (`CON.` → `CON`
///    açar, reserved check bypass'ı); bu yüzden sondan kırpılır.
/// 5. Windows reserved adları **ilk** nokta öncesi stem üzerinde kontrol
///    edilir (`split_name`'in son-nokta mantığı `CON.tar.gz`'yi kaçırır).
///    Kapsam: CON, PRN, AUX, NUL, COM1..9, LPT1..9, CONIN$, CONOUT$,
///    CLOCK$. Eşleşme → `_` prefix (`CON.tar.gz` → `_CON.tar.gz`).
/// 6. 200 bayttan uzun adlar UTF-8 boundary'de truncate edilir.
/// 7. Sonuç boşsa `dosya` döner.
fn sanitize_received_name(name: &str) -> String {
    // 1. Basename: her iki separator için rightmost sonrası.
    let after_fwd = name.rsplit('/').next().unwrap_or(name);
    let base = after_fwd.rsplit('\\').next().unwrap_or(after_fwd);

    // 2. `.`/`..` geçersiz.
    let trimmed = base.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "dosya".into();
    }

    // 3. NUL + control + Windows yasaklı karakterleri filtrele.
    let cleaned: String = trimmed
        .chars()
        .filter(|&c| {
            c >= ' '
                && c != '\x7f'
                && !matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
        .collect();
    if cleaned.is_empty() {
        return "dosya".into();
    }

    // 4. Trailing dot/space'i kırp — Windows'un reserved check bypass'ına
    //    karşı koruma (`CON.` / `CON ` Windows'ta `CON` açar).
    let cleaned = cleaned
        .trim_end_matches(|c: char| c == '.' || c.is_whitespace())
        .to_string();
    if cleaned.is_empty() {
        return "dosya".into();
    }

    // 5. Reserved device names — **ilk** nokta öncesi stem üzerinde kontrol.
    let stem_for_reserved = cleaned.split('.').next().unwrap_or(&cleaned);
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
        "CONOUT$", "CLOCK$",
    ];
    let cleaned = if reserved
        .iter()
        .any(|r| stem_for_reserved.eq_ignore_ascii_case(r))
    {
        format!("_{cleaned}")
    } else {
        cleaned
    };

    // 6. Uzunluk limiti (UTF-8 boundary'ye saygılı).
    let max_bytes = 200usize;
    if cleaned.len() <= max_bytes {
        return cleaned;
    }
    let mut cut = max_bytes;
    while cut > 0 && !cleaned.is_char_boundary(cut) {
        cut -= 1;
    }
    cleaned[..cut].to_string()
}

/// URL payload'ı için güvenli şema kontrolü.
///
/// **Neden gerekli:** `TextType::Url` gelince `open_url()` çağrılıyor;
/// OS varsayılan tarayıcıya giderse `javascript:` browser'da kod çalıştırır,
/// `file://` local dosyaya erişir (exfiltration), `smb://` Windows'ta NTLM
/// credential leak'e çevrilir, özel protocol handler'lar (zoom-us, steam,
/// registry custom protokoller) arbitrary app tetikler. Yalnız http/https
/// kabul et.
fn is_safe_url_scheme(url: &str) -> bool {
    let trimmed = url.trim_start();
    let starts = |prefix: &str| {
        trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix)
    };
    starts("http://") || starts("https://")
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

pub(crate) fn build_paired_key_encryption(state: &AppState) -> SharingFrame {
    // Issue #17: `secret_id_hash` artık random değil — cihaz-kalıcı
    // `DeviceIdentity.long_term_key` üzerinden HKDF-SHA256 ile türetilir.
    // Peer bu değeri bizim "stabil kimlik"imiz olarak görür ve trusted
    // listesinde bu hash'e bağlı saklar.
    //
    // `signed_data` hâlâ random — v0.7'de pairing protokolüyle gerçek
    // ECDSA imza (long-term signing key) eklenecek. Şimdilik peer'lar
    // alanı doğrulamıyor (bizim tarafta da doğrulamıyoruz; bkz.
    // design 017 §5.5 / §9 answer #2).
    let hash = state.identity.secret_id_hash();
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::PairedKeyEncryption as i32),
            paired_key_encryption: Some(PairedKeyEncryptionFrame {
                secret_id_hash: Some(hash.to_vec().into()),
                // TODO(v0.7): signing_key() ile ECDSA imza + peer pubkey
                // doğrulaması pairing protokolüyle birlikte.
                signed_data: Some(random_bytes(72).into()),
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
    // SAFETY-CAST: u64 >> 1 her zaman 0..=i64::MAX aralığında — high bit
    // shift ile sıfırlanıyor, wrap yok.
    #[allow(clippy::cast_possible_wrap)]
    let payload_id: i64 = (rand::thread_rng().next_u64() >> 1) as i64;
    let total = i64::try_from(body.len())
        .with_context(|| format!("sharing frame body i64'a sığmıyor: {} bayt", body.len()))?;

    // İlk chunk: tam gövde, offset=0, flags=0.
    // `body` bu satırdan sonra kullanılmıyor → clone yerine move (alokasyon
    // yarıya iner; küçük frame'lerde önemli değil ama hot path hijyeni).
    let first = wrap_payload_transfer(payload_id, total, 0, 0, body);
    let enc1 = ctx.encrypt(&first.encode_to_vec())?;
    frame::write_frame(socket, &enc1).await?;

    // Son chunk: boş gövde, flags=1 (last)
    let last = wrap_payload_transfer(payload_id, total, total, 1, Vec::new());
    let enc2 = ctx.encrypt(&last.encode_to_vec())?;
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
                    body: Some(body.into()),
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

/// UKEY2 handshake sırasında oluşan hatayı kullanıcıya gösterilecek
/// i18n key'ine sınıflandırır. Downcast önceliği: önce
/// [`crate::error::HekaError`] variant'ları (tip-safe ayrım), sonra
/// `std::io::Error` (generic I/O). String-match son çare değil — düşmüyoruz,
/// fallback kasıtlı olarak `err.pin_mismatch`: UKEY2 handshake spec'inde
/// handshake tamamlansa ama `ClientFinished` commitment reddedilse bu noktada
/// `Ukey2CommitmentMismatch` downcast yakalar; bilinmeyen generic hata
/// kullanıcı için de pratikte "PIN eşleşmedi" olarak yorumlanır (en sık neden).
fn classify_handshake_error(e: &anyhow::Error) -> &'static str {
    fn map_io_error(io: &std::io::Error) -> &'static str {
        use std::io::ErrorKind::*;
        // API: Explicit liste DOKÜMANTASYON: tanıdığımız peer-disconnect
        // semantikli io error variants. Wildcard ile aynı body'ye düşse de
        // bilinen kindleri ayrı listelemek "şu hatalar = peer disconnect"
        // anlamını taşır; gelecekte ayrı i18n key ayrımı (network vs. abort)
        // kolaylaşır. clippy::match_same_arms `_ => ...`'a indirmeyi öneriyor —
        // anlam kaybı.
        #[allow(clippy::match_same_arms)]
        match io.kind() {
            TimedOut => "err.peer_timeout",
            ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected => {
                "err.peer_disconnected"
            }
            _ => "err.peer_disconnected",
        }
    }
    // HekaError::Io(#[from] std::io::Error) thiserror `source()` zinciri
    // ürettiği için iç `io::Error` aşağıdaki generic io downcast dalında
    // yakalanır — HekaError::Io özel bir kolu gereksiz (PR #79 gemini review).
    for cause in e.chain() {
        if let Some(he) = cause.downcast_ref::<HekaError>() {
            match he {
                HekaError::ReadTimeout(_) => return "err.peer_timeout",
                HekaError::UnexpectedEof | HekaError::PeerDisconnected => {
                    return "err.peer_disconnected"
                }
                HekaError::Ukey2CommitmentMismatch => return "err.pin_mismatch",
                HekaError::Ukey2CipherDowngrade(_)
                | HekaError::Ukey2VersionDowngrade(_)
                | HekaError::Ukey2(_)
                | HekaError::CipherCommitmentFlood(_)
                | HekaError::ProtocolState(_) => return "err.handshake_insecure",
                _ => {}
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return map_io_error(io);
        }
    }
    "err.pin_mismatch"
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

/// Receiver tarafı progress yüzdesi — peer'den gelen `offset`, `total_size` ve
/// chunk body uzunluğu (usize) ile 0..=100 aralığında u8 hesabı.
///
/// **Why checked aritmetik:** Üç giriş alanı da unvalidated peer data. Naïve
/// `(offset + body_len) * 100 / total` hesabı i64 overflow ile (debug panic /
/// release wrap) yanlış progress veya `DoS` açar. Overflow ya da geçersiz `total`
/// (0/negatif) → `None` (caller progress update'ini sessizce atlar).
///
/// Bkz. [`crate::sender::compute_percent`] sender tarafı muadili (`bytes_before`
/// + `offset` farklı semantik). Birleştirme için RFC gerekir.
fn compute_recv_percent(offset: i64, body_len: usize, total: i64) -> Option<u8> {
    if total <= 0 {
        return None;
    }
    let body_len_i64 = i64::try_from(body_len).ok()?;
    let written = offset.checked_add(body_len_i64)?;
    let scaled = written.checked_mul(100)?;
    let raw = scaled.checked_div(total)?;
    u8::try_from(raw.clamp(0, 100)).ok()
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
            .map_or(0, |d| d.as_nanos());
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
        asm.register_file_destination(101, p1.clone()).unwrap();
        asm.register_file_destination(202, p2.clone()).unwrap();
        names.insert(101, "a.bin".into());
        names.insert(202, "b.bin".into());
        texts.insert(303, TextType::Text);

        let cleaned = drain_pending(&mut asm, &mut names, &mut texts);

        assert_eq!(cleaned, 2, "iki yarım dosya temizlenmeliydi");
        assert!(names.is_empty(), "pending_names sıfırlanmalı");
        assert!(texts.is_empty(), "pending_texts sıfırlanmalı");
        // Regresyon (Copilot review): `drain_pending` yalnız haritaları
        // boşaltmakla yetinmemeli — `assembler.cancel(id)` üzerinden kayıtlı
        // hedef dosyayı diskten de silmeli. Aksi halde reject / cancel
        // yolunda indirme klasöründe 0-bayt placeholder'lar birikir.
        assert!(
            !p1.exists(),
            "drain_pending dosyayı silmemiş: {}",
            p1.display()
        );
        assert!(
            !p2.exists(),
            "drain_pending dosyayı silmemiş: {}",
            p2.display()
        );
    }

    #[tokio::test]
    async fn drain_pending_acik_dosya_sinkini_siler() {
        // İlk chunk gelmiş → dosya create edilmiş → sonra reject/cancel.
        let mut asm = PayloadAssembler::new();
        let mut names: HashMap<i64, String> = HashMap::new();
        let mut texts: HashMap<i64, TextType> = HashMap::new();

        let p = unique_tmp("partial.bin");
        asm.register_file_destination(777, p.clone()).unwrap();
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
        asm.ingest(&chunk_frame).await.unwrap();

        assert!(p.exists(), "assembler ilk chunk'ı diske yazmış olmalı");

        let cleaned = drain_pending(&mut asm, &mut names, &mut texts);
        assert_eq!(cleaned, 1);
        assert!(
            !p.exists(),
            "yarım kalan dosya reject sonrası silinmiş olmalı"
        );
    }

    // ------------------------------------------------------------------
    // Security: sanitize_received_name + is_safe_url_scheme
    // ------------------------------------------------------------------

    #[test]
    fn sanitize_normal_ad_degismez() {
        assert_eq!(sanitize_received_name("rapor.pdf"), "rapor.pdf");
        assert_eq!(sanitize_received_name("foto.jpg"), "foto.jpg");
    }

    #[test]
    fn sanitize_unix_path_traversal_basename_a_duser() {
        assert_eq!(sanitize_received_name("../../../etc/passwd"), "passwd");
        assert_eq!(sanitize_received_name("/etc/shadow"), "shadow");
        assert_eq!(sanitize_received_name("foo/bar.txt"), "bar.txt");
    }

    #[test]
    fn sanitize_windows_path_traversal_basename_a_duser() {
        assert_eq!(
            sanitize_received_name(r"C:\Windows\System32\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(
            sanitize_received_name(r"..\..\autostart\evil.bat"),
            "evil.bat"
        );
        assert_eq!(
            sanitize_received_name(r"mixed/forward\back.txt"),
            "back.txt"
        );
    }

    #[test]
    fn sanitize_null_ve_control_karakter_temizlenir() {
        assert_eq!(sanitize_received_name("abc\0def.txt"), "abcdef.txt");
        assert_eq!(sanitize_received_name("line1\nline2.txt"), "line1line2.txt");
        assert_eq!(sanitize_received_name("tab\ttab.txt"), "tabtab.txt");
    }

    #[test]
    fn sanitize_sirf_nokta_gecersiz() {
        assert_eq!(sanitize_received_name("."), "dosya");
        assert_eq!(sanitize_received_name(".."), "dosya");
        assert_eq!(sanitize_received_name(""), "dosya");
        assert_eq!(sanitize_received_name("   "), "dosya");
    }

    #[test]
    fn sanitize_windows_reserved_adlar_prefix_alir() {
        assert_eq!(sanitize_received_name("CON"), "_CON");
        assert_eq!(sanitize_received_name("PRN.txt"), "_PRN.txt");
        assert_eq!(sanitize_received_name("com1"), "_com1");
        assert_eq!(sanitize_received_name("LPT9.log"), "_LPT9.log");
        // Reserved olmayan
        assert_eq!(sanitize_received_name("CONSOLE.txt"), "CONSOLE.txt");
        assert_eq!(sanitize_received_name("COMMAND"), "COMMAND");
    }

    #[test]
    fn sanitize_reserved_coklu_uzanti_bypass_engellenir() {
        // `split_name` son-nokta alır → `CON.tar` stem'i; ilk-nokta taramasıyla
        // `CON` yakalanır. Bu testler 0.5.1 Gemini/Copilot review'ından geldi.
        assert_eq!(sanitize_received_name("CON.tar.gz"), "_CON.tar.gz");
        assert_eq!(sanitize_received_name("nul.tar.bz2"), "_nul.tar.bz2");
        assert_eq!(sanitize_received_name("aux.tar"), "_aux.tar");
    }

    #[test]
    fn sanitize_reserved_ek_device_adlari() {
        assert_eq!(sanitize_received_name("CONIN$"), "_CONIN$");
        assert_eq!(sanitize_received_name("CONOUT$"), "_CONOUT$");
        assert_eq!(sanitize_received_name("CLOCK$.txt"), "_CLOCK$.txt");
        // Case-insensitive
        assert_eq!(sanitize_received_name("conin$"), "_conin$");
    }

    #[test]
    fn sanitize_trailing_dot_space_bypass_engellenir() {
        // Windows trailing `.` ve space'i yok sayar → `CON.` aslında `CON`
        // açar. Trim edilmeli, sonra reserved check yakalanmalı.
        assert_eq!(sanitize_received_name("CON."), "_CON");
        assert_eq!(sanitize_received_name("CON "), "_CON");
        assert_eq!(sanitize_received_name("CON.txt."), "_CON.txt");
        assert_eq!(sanitize_received_name("CON...  "), "_CON");
        // Normal dosyada da trailing dot kaybolur
        assert_eq!(sanitize_received_name("rapor.pdf."), "rapor.pdf");
    }

    #[test]
    fn sanitize_windows_yasakli_karakterler_filtrelenir() {
        // ADS vektörü: `:`
        assert_eq!(sanitize_received_name("ok.txt:evil"), "ok.txtevil");
        // Diğer Windows yasakları
        assert_eq!(sanitize_received_name("a<b>c.txt"), "abc.txt");
        assert_eq!(sanitize_received_name("wild*card?.dat"), "wildcard.dat");
        assert_eq!(sanitize_received_name(r#"say"hi""#), "sayhi");
        assert_eq!(sanitize_received_name("a|b.txt"), "ab.txt");
    }

    #[test]
    fn sanitize_uzunluk_siniri_200_byte() {
        let very_long = "a".repeat(500);
        let out = sanitize_received_name(&very_long);
        assert!(out.len() <= 200);
    }

    #[test]
    fn sanitize_utf8_boundary_korunur() {
        // "ş" 2 byte; toplam 300 byte. Kesim char boundary'de kalmalı
        // (panic yapmamalı, invalid UTF-8 üretmemeli).
        let s = "ş".repeat(150);
        let out = sanitize_received_name(&s);
        assert!(out.len() <= 200);
        // Lossless UTF-8
        let _ = out.chars().count();
    }

    #[test]
    fn sanitize_turkce_karakterler_korunur() {
        assert_eq!(
            sanitize_received_name("çok önemli dosya.pdf"),
            "çok önemli dosya.pdf"
        );
    }

    #[test]
    fn url_safe_scheme_http_https_evet() {
        assert!(is_safe_url_scheme("http://example.com"));
        assert!(is_safe_url_scheme("https://example.com"));
        assert!(is_safe_url_scheme("HTTPS://EXAMPLE.COM"));
        assert!(is_safe_url_scheme("  https://example.com"));
    }

    // ------------------------------------------------------------------
    // Privacy: log_redact helper'ına kısaltma regression'ları. Log dosyası
    // 3 gün rolling retention + troubleshooting sırasında paylaşılabilir,
    // bu yüzden `info!` / `warn!` satırlarının tam path / tam SHA-256 /
    // URL query içermemesi garanti altında.
    // ------------------------------------------------------------------

    #[test]
    fn redact_path_basename_only() {
        let p = std::path::PathBuf::from("/home/user/Belgeler/secret.pdf");
        assert_eq!(crate::log_redact::path_basename(&p), "secret.pdf");
    }

    #[test]
    fn redact_sha_short_form() {
        let sha = "a".repeat(64);
        let short = crate::log_redact::sha_short(&sha);
        assert_eq!(short.len(), 16);
        assert!(sha.starts_with(short));
    }

    #[test]
    fn redact_url_scheme_host_only() {
        assert_eq!(
            crate::log_redact::url_scheme_host("https://example.com/path?token=abc"),
            "https://example.com"
        );
    }

    #[test]
    fn url_unsafe_scheme_javascript_file_smb() {
        assert!(!is_safe_url_scheme("javascript:alert(1)"));
        assert!(!is_safe_url_scheme("JavaScript:alert(1)"));
        assert!(!is_safe_url_scheme("file:///etc/passwd"));
        assert!(!is_safe_url_scheme("smb://attacker/share"));
        assert!(!is_safe_url_scheme("data:text/html,<script>"));
        assert!(!is_safe_url_scheme("vbscript:msgbox"));
        // Windows custom protocol handlers
        assert!(!is_safe_url_scheme("ms-msdt:/id PCWDiagnostic"));
        assert!(!is_safe_url_scheme("zoom-us://foo"));
        // Boş/anlamsız
        assert!(!is_safe_url_scheme(""));
        assert!(!is_safe_url_scheme("http"));
        assert!(!is_safe_url_scheme("://example.com"));
    }

    /// `compute_recv_percent` security-critical helper — peer'den gelen
    /// unvalidated `offset` + `body_len` + `total` ile checked aritmetik
    /// yapıyor. Her code path için en az bir vektör; overflow korumasını da
    /// kapatıyor.
    ///
    /// Bkz. PR #88 review (Gemini medium-priority + Copilot): test eksikti.
    #[test]
    fn compute_recv_percent_normal_cases() {
        // Yarı yol: offset=0, body=500, total=1000 → 500/1000 = 50%
        assert_eq!(compute_recv_percent(0, 500, 1000), Some(50));
        // Tam: offset=500, body=500, total=1000 → 100%
        assert_eq!(compute_recv_percent(500, 500, 1000), Some(100));
        // Başlangıç: offset=0, body=0, total=1000 → 0%
        assert_eq!(compute_recv_percent(0, 0, 1000), Some(0));
        // Round-down: 333/1000 = 33.3% → 33 (i64 div truncates)
        assert_eq!(compute_recv_percent(0, 333, 1000), Some(33));
    }

    #[test]
    fn compute_recv_percent_invalid_total_returns_none() {
        // total = 0 → caller progress update'ini atlamalı (DivByZero koruması)
        assert_eq!(compute_recv_percent(0, 0, 0), None);
        // total negatif (peer protokol ihlali) → None
        assert_eq!(compute_recv_percent(0, 100, -1), None);
        assert_eq!(compute_recv_percent(0, 100, i64::MIN), None);
    }

    #[test]
    fn compute_recv_percent_clamps_out_of_range() {
        // Negatif offset (peer ihlali) → written negatif → clamp(0,100)=0
        assert_eq!(compute_recv_percent(-10, 5, 100), Some(0));
        // written > total → percent > 100 → clamp(0,100)=100
        assert_eq!(compute_recv_percent(2000, 0, 1000), Some(100));
    }

    #[test]
    fn compute_recv_percent_overflow_returns_none() {
        // checked_add overflow: offset=i64::MAX, body=1 → +1 wrap → None
        assert_eq!(compute_recv_percent(i64::MAX, 1, i64::MAX), None);
        // checked_mul overflow: i64::MAX/2 * 100 → wrap → None
        assert_eq!(compute_recv_percent(i64::MAX / 2, 0, i64::MAX), None);
        // body_len = usize::MAX (64-bit'te i64'e sığmaz) → try_from None
        assert_eq!(compute_recv_percent(0, usize::MAX, 1000), None);
    }

    // ─── PR #114 (CRITICAL): receiver dispatch + capabilities response ───

    /// `dispatch_frame_body` `HekaDrop` magic (`0xA5DEB201`) içeren plaintext
    /// için `FrameKind::HekaDrop` döner; capabilities exchange wire path
    /// bunu kullanır. Receiver loop bu varyanta opportunistic handler ile
    /// cevap verir.
    #[test]
    fn dispatch_recognizes_hekadrop_magic_prefix() {
        use hekadrop_proto::hekadrop_ext::{heka_drop_frame::Payload, Capabilities, HekaDropFrame};
        use prost::Message;

        let caps = HekaDropFrame {
            version: 1,
            payload: Some(Payload::Capabilities(Capabilities {
                version: 1,
                features: 0x0007,
            })),
        };
        let pb = caps.encode_to_vec();
        let wrapped = crate::frame::wrap_hekadrop_frame(&pb);

        match crate::frame::dispatch_frame_body(&wrapped) {
            crate::frame::FrameKind::HekaDrop { inner } => {
                let parsed = HekaDropFrame::decode(inner).expect("re-decode");
                assert_eq!(parsed.version, 1);
                match parsed.payload.expect("payload") {
                    Payload::Capabilities(c) => assert_eq!(c.features, 0x0007),
                    _ => panic!("expected Capabilities payload"),
                }
            }
            crate::frame::FrameKind::Offline { .. } => {
                panic!("HekaDrop frame should NOT be classified as Offline")
            }
        }
    }

    /// Magic prefix taşımayan ham `OfflineFrame` body'si `Offline` varyantı
    /// olarak sınıflandırılmalı. PR #114 fix'i bu path'i bozmaz — legacy
    /// Quick Share peer'ları için mevcut akış aynen çalışır.
    #[test]
    fn dispatch_recognizes_offline_frame() {
        // Magic OLMAYAN bytes — herhangi bir non-magic prefix
        let body: Vec<u8> = vec![0x08, 0x01, 0x12, 0x00]; // Quick Share OfflineFrame benzeri
        match crate::frame::dispatch_frame_body(&body) {
            crate::frame::FrameKind::Offline { body: b } => {
                assert_eq!(b, &[0x08, 0x01, 0x12, 0x00]);
            }
            crate::frame::FrameKind::HekaDrop { .. } => {
                panic!("non-magic body should be classified as Offline")
            }
        }
    }

    /// Boş body veya 4 byte'tan kısa body Offline varyantı (magic
    /// karşılaştırması yapılamaz).
    #[test]
    fn dispatch_short_body_falls_to_offline() {
        for short in [
            &[][..],
            &[0xA5][..],
            &[0xA5, 0xDE][..],
            &[0xA5, 0xDE, 0xB2][..],
        ] {
            match crate::frame::dispatch_frame_body(short) {
                crate::frame::FrameKind::Offline { .. } => {}
                crate::frame::FrameKind::HekaDrop { .. } => {
                    panic!(
                        "short body (<4) should be Offline, got HekaDrop for len={}",
                        short.len()
                    )
                }
            }
        }
    }
}
