//! Sharing-layer frame dispatcher + Introduction/consent karar mantığı.
//!
//! Bu modül şifreli loop'ta gelen `SharingFrame`'leri işler:
//!   * `PairedKeyEncryption` → peer'ın `secret_id_hash`'i yakalanır.
//!   * `Introduction` → kullanıcıya dialog, trust kararı, placeholder rezervasyonu.
//!   * `Cancel` → akış sonlandırma sinyali.
//!
//! `handle_sharing_frame` akış sonucunu `FlowOutcome` ile üst loop'a bildirir.

use super::frames::{
    build_consent_accept, build_consent_reject, build_paired_key_result, build_sharing_cancel,
    send_sharing_frame,
};
use super::sanitize::unique_downloads_path;
use crate::error::HekaError;
use crate::payload::PayloadAssembler;
use crate::secure::SecureCtx;
use crate::sharing::nearby::{
    text_metadata::Type as TextType, v1_frame as sh_v1, Frame as SharingFrame,
};
use crate::state;
use crate::ui;
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{info, warn};

#[derive(PartialEq, Eq)]
pub(crate) enum FlowOutcome {
    Continue,
    Disconnect,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_sharing_frame(
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

            // Legacy → hash migration tespiti:
            //   Peer hash gönderdi (Some) + hash henüz güvenilirler arasında
            //   değil + aynı (name, id) legacy kayıt olarak zaten güvenilir.
            //   Bu, v0.5'te güvenilen bir cihazın v0.6 ile ilk bağlantısı —
            //   kullanıcıya *neden* bir dialog gördüğünü açıklamak için
            //   önceden kısa bir migration bildirimi gönderiyoruz.
            //
            //   `ui::prompt_accept()` şu an custom title+body parametresi
            //   almıyor (cross-platform blocking fn; imza genişletmesi Dalga
            //   3 işi). Fallback: dialog'tan hemen önce `ui::notify` ile
            //   bağlamı kullanıcıya iletiyoruz.
            let migration_hint = peer_secret_id_hash.is_some() && !trusted && {
                let st = state::get();
                let s = st.settings.read();
                // Güvenli: yukarıdaki `trusted` bloğu peer_secret_id_hash
                // Some iken is_trusted_by_hash'i kontrol ediyor — burada
                // tekrarlamaya gerek yok; Some+!trusted zaten hash-miss.
                s.is_trusted_legacy(remote_name, remote_id)
            };

            let auto_accept = state::get().settings.read().auto_accept;

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
                    match peer_secret_id_hash {
                        Some(h) => {
                            s.add_trusted_with_hash(remote_name, remote_id, *h);
                        }
                        None => {
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
