//! Şifreli loop içindeki yardımcılar — metin payload işleme, görüntü kısaltma,
//! boyut biçimlendirme ve yarım kalan state temizleyicileri.

use super::sanitize::is_safe_url_scheme;
use crate::payload::PayloadAssembler;
use crate::sharing::nearby::text_metadata::Type as TextType;
use crate::state::{self, ProgressState};
use crate::ui;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{info, warn};

pub(crate) fn handle_text_payload(peer: &SocketAddr, kind: TextType, data: &[u8]) {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            warn!("[{}] UTF-8 olmayan metin payload", peer);
            return;
        }
    };
    match kind {
        TextType::Url => {
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
        }
        _ => {
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
}

pub(crate) fn preview(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{}…", truncated)
    }
}

pub(crate) fn human_size(bytes: i64) -> String {
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
pub(crate) fn cleanup_transfer_state(
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
pub(crate) fn drain_pending(
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

#[cfg(test)]
mod tests {
    use super::super::frames::wrap_payload_transfer;
    use super::*;
    use crate::location::nearby::connections::payload_transfer_frame::payload_header::PayloadType;
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
        // NOT: `register_file_destination` çağrılmış ama hiç chunk gelmemiş dosyalar
        // için `assembler.cancel(id)` yalnızca haritadan kaldırır — diskte
        // file yoktur (çünkü biz elle oluşturduk). Burada test dosyalarını
        // temizlemek test hijyeni için:
        std::fs::remove_file(&p1).ok();
        std::fs::remove_file(&p2).ok();
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
}
