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
    // `TransferGuard::new()` içinde auto clear_cancel — bu bağlantıya özel
    // child token hem taze root'a hem de scope sonunda active_transfers
    // map'inden otomatik temizliğe (early-return yollarında bile) garanti verir.
    let guard = state::TransferGuard::new(format!("in:{}", peer));
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
    let st = state::get();
    if st.rate_limiter.check_and_record(peer.ip()) {
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
            ui::notify(crate::i18n::t("notify.app_name"), crate::i18n::t(key));
            state::set_progress(ProgressState::Idle);
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
                        let body_len_usize = chunk.body.as_ref().map(|b| b.len()).unwrap_or(0);
                        // SECURITY: peer'den gelen `offset` + `body_len` + `total`
                        // alanları unvalidated. `*100` ve `+` operasyonlarını
                        // checked aritmetikle koru; overflow olursa progress
                        // update'ini sessizce atla (DoS koruması — debug build
                        // panic, release wrap, ikisi de istenmiyor).
                        if let Some(percent) = compute_recv_percent(offset, body_len_usize, total) {
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
                                    // payload.rs ingest_file aşamasında `total_size < 0` reddediliyor — burada >= 0 garanti.
                                    #[allow(clippy::cast_sign_loss)]
                                    let total_size_u = total_size as u64;
                                    s.record_received(&remote_name_shared, total_size_u);
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
    );

    Ok(())
}

/// Yarım kalan alıcı state'ini temizler.
///
/// Reject, kullanıcı Cancel, peer Disconnect, I/O hatası veya socket
/// kopması durumlarının hepsinde güvenli biçimde çağrılır; idempotent'tir.
/// Yaptığı işler:
///   * `pending_names` içindeki her payload_id için `PayloadAssembler::cancel`
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
) {
    let n = drain_pending(assembler, pending_names, pending_texts);
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
    peer_secret_id_hash: &mut Option<[u8; 6]>,
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
                let s = state::get();
                if s.settings.read().is_trusted_by_hash(&h) {
                    s.rate_limiter.forget_most_recent(peer.ip());
                    info!(
                        "[{}] trusted hash doğrulandı — rate-limit kaydı geri alındı",
                        peer
                    );
                }
            }
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

            let mut summaries: Vec<ui::FileSummary> = Vec::new();
            let mut planned_files: Vec<(i64, std::path::PathBuf, String)> = Vec::new();
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
                        for (_pid, path, _name) in &planned_files {
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
                let st = state::get();
                let s = st.settings.read();
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

            let auto_accept = state::get().settings.read().auto_accept;

            // Dalga 3 UX: Peer hash göndermiş olduğu halde hash kayıtta yoksa,
            // `(name, id)` legacy kaydı varsa — bu "v0.5 → v0.6 migration"
            // senaryosudur. Dialog açılmadan önce kullanıcıya nedenini
            // açıklayan bir bildirim gönder; aksi halde tanıdık cihaz için
            // birden dialog görünce "güveni zedelenmiş mi?" tereddüdü doğar.
            let migration_hint = peer_secret_id_hash.is_some() && !trusted && {
                let st = state::get();
                let s = st.settings.read();
                s.is_trusted_legacy(remote_name, remote_id)
            };

            let decision = if trusted {
                info!("[{}] trusted cihaz → otomatik kabul", peer);
                // Sliding-window TTL: aktif kullanım varsa timestamp'i yenile.
                if let Some(h) = peer_secret_id_hash {
                    let st = state::get();
                    let snap = {
                        let mut s = st.settings.write();
                        s.touch_trusted_by_hash(h);
                        s.clone()
                    };
                    let _ = snap.save();
                }
                ui::AcceptResult::Accept
            } else if auto_accept {
                info!("[{}] settings.auto_accept=true → otomatik kabul", peer);
                ui::AcceptResult::Accept
            } else {
                if migration_hint {
                    info!(
                        "[{}] legacy → hash migration dialog'u gösteriliyor: {}",
                        peer, remote_name
                    );
                    ui::notify(
                        crate::i18n::t("trust.migration.title"),
                        &crate::i18n::tf("trust.migration.body", &[remote_name, pin_code]),
                    );
                }
                ui::prompt_accept(remote_name, pin_code, &summaries, text_count)
                    .await
                    .unwrap_or(ui::AcceptResult::Reject)
            };

            let ok = !matches!(decision, ui::AcceptResult::Reject);
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
            if matches!(decision, ui::AcceptResult::Accept) {
                if let Some(h) = peer_secret_id_hash {
                    let needs_upgrade = {
                        let st = state::get();
                        let s = st.settings.read();
                        s.is_trusted_legacy(remote_name, remote_id) && !s.is_trusted_by_hash(h)
                    };
                    if needs_upgrade {
                        let st = state::get();
                        let snap = {
                            let mut s = st.settings.write();
                            s.add_trusted_with_hash(remote_name, remote_id, *h);
                            s.clone()
                        };
                        let _ = snap.save();
                        info!(
                            "[{}] legacy trust kaydı secret_id_hash ile yükseltildi: {}",
                            peer, remote_name
                        );
                    }
                }
            }

            if matches!(decision, ui::AcceptResult::AcceptAndTrust) {
                let st = state::get();
                let snap = {
                    let mut s = st.settings.write();
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
                let _ = snap.save();
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
                    assembler
                        .register_file_destination(pid, path)
                        .context("dosya hedefi kaydı")?;
                    pending_names.insert(pid, display_name);
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
                for (_pid, path, _name) in &planned_files {
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
    let text = if let Ok(s) = std::str::from_utf8(data) {
        s.trim().to_string()
    } else {
        warn!("[{}] UTF-8 olmayan metin payload", peer);
        return;
    };
    if kind == TextType::Url {
        if is_safe_url_scheme(&text) {
            crate::platform::open_url(&text);
            // PRIVACY: Log dosyasına yalnız şema + host düşer; path + query
            // (token içerebilir) redact. UI bildirimi kullanıcının kendi
            // ekranında olduğu için tam preview'la gösterilir.
            info!(
                "[{}] URL açıldı: {}",
                peer,
                crate::log_redact::url_scheme_host(&text)
            );
            ui::notify(
                crate::i18n::t("notify.app_name"),
                &crate::i18n::tf("notify.url_opened", &[&preview(&text, 80)]),
            );
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
            crate::platform::copy_to_clipboard(&text);
            ui::notify(
                crate::i18n::t("notify.app_name"),
                &crate::i18n::tf("notify.text_clipboard", &[&preview(&text, 80)]),
            );
        }
    } else {
        crate::platform::copy_to_clipboard(&text);
        info!(
            "[{}] metin panoya kopyalandı ({} karakter)",
            peer,
            text.len()
        );
        ui::notify(
            crate::i18n::t("notify.app_name"),
            &crate::i18n::tf("notify.text_clipboard", &[&preview(&text, 80)]),
        );
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
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", n, UNITS[i])
    }
}

fn unique_downloads_path(name: &str) -> Result<PathBuf> {
    let base = state::get().settings.read().resolved_download_dir();
    std::fs::create_dir_all(&base).ok();

    // SECURITY: Uzak cihazdan gelen dosya adı saldırgan kontrolünde; doğrudan
    // `base.join(name)` path traversal'a açıktır — sanitize ile yalnız
    // basename kalır, `..`/`/`/`\`/NUL/control char silinir, Windows
    // reserved adları (CON, PRN…) yeniden adlandırılır.
    let safe = sanitize_received_name(name);

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

    let candidate = base.join(&safe);
    match try_reserve(&candidate) {
        Ok(()) => return Ok(candidate),
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(anyhow!("dosya rezerve edilemedi: {}", e));
        }
        Err(_) => {}
    }

    let (stem, ext) = split_name(&safe);
    let mut n = 1;
    loop {
        let filename = if ext.is_empty() {
            format!("{} ({})", stem, n)
        } else {
            format!("{} ({}).{}", stem, n, ext)
        };
        let next = base.join(filename);
        match try_reserve(&next) {
            Ok(()) => return Ok(next),
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(anyhow!("dosya rezerve edilemedi: {}", e));
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
        format!("_{}", cleaned)
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

pub(crate) fn build_paired_key_encryption() -> SharingFrame {
    // Issue #17: `secret_id_hash` artık random değil — cihaz-kalıcı
    // `DeviceIdentity.long_term_key` üzerinden HKDF-SHA256 ile türetilir.
    // Peer bu değeri bizim "stabil kimlik"imiz olarak görür ve trusted
    // listesinde bu hash'e bağlı saklar.
    //
    // `signed_data` hâlâ random — v0.7'de pairing protokolüyle gerçek
    // ECDSA imza (long-term signing key) eklenecek. Şimdilik peer'lar
    // alanı doğrulamıyor (bizim tarafta da doğrulamıyoruz; bkz.
    // design 017 §5.5 / §9 answer #2).
    let hash = state::get().identity.secret_id_hash();
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
    let payload_id: i64 = (rand::thread_rng().next_u64() >> 1) as i64;
    let total = body.len() as i64;

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
/// handshake tamamlansa ama ClientFinished commitment reddedilse bu noktada
/// `Ukey2CommitmentMismatch` downcast yakalar; bilinmeyen generic hata
/// kullanıcı için de pratikte "PIN eşleşmedi" olarak yorumlanır (en sık neden).
fn classify_handshake_error(e: &anyhow::Error) -> &'static str {
    fn map_io_error(io: &std::io::Error) -> &'static str {
        use std::io::ErrorKind::*;
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
/// release wrap) yanlış progress veya DoS açar. Overflow ya da geçersiz `total`
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
}
