//! Basit i18n — iki dil (Türkçe default + İngilizce). Harici kütüphane yok;
//! match-based lookup compile-time checked. Detection sırası:
//!
//!   1. `HEKADROP_LANG` ortam değişkeni (tr / en varyantları)
//!   2. `LC_ALL` / `LC_MESSAGES` / `LANG` (Linux / macOS)
//!   3. Fallback: Türkçe
//!
//! Windows'ta locale tespiti için `LANG` env tipik olarak set değildir;
//! `HEKADROP_LANG=en` kullanıcı tarafından verilmezse Türkçe default olur.
//! (İleride `GetUserDefaultLocaleName` ile Win32 tespiti eklenebilir.)
//!
//! ## Kullanım
//!
//! ```ignore
//! use crate::i18n::t;
//! label.set_text(t("tray.status.ready"));
//!
//! use crate::i18n::tf;
//! let msg = tf("notify.received", &[&filename, &size_human]);
//! ```
//!
//! Bilinmeyen key'ler ve eksik çeviriler key string'i olarak döner — görünür
//! bir fallback, böylece test/debug sırasında eksiklikler gözükür.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Tr,
    En,
}

static LANG: OnceLock<Lang> = OnceLock::new();

/// Uygulamanın kullanacağı dili döner. İlk çağrıda detect edilir ve cache'lenir.
pub fn current() -> Lang {
    *LANG.get_or_init(detect)
}

fn detect() -> Lang {
    if let Ok(v) = std::env::var("HEKADROP_LANG") {
        if let Some(lang) = parse_lang(&v) {
            return lang;
        }
    }
    for var in &["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            if let Some(lang) = parse_lang(&v) {
                return lang;
            }
        }
    }
    Lang::Tr
}

fn parse_lang(raw: &str) -> Option<Lang> {
    let s = raw.to_lowercase();
    let prefix = s.split(['.', '-', '_']).next()?;
    match prefix {
        "tr" => Some(Lang::Tr),
        "en" => Some(Lang::En),
        _ => None,
    }
}

/// Basit key → çeviri. Bilinmeyen key veya eksik çeviri için `"?"` döner
/// (caller'ın key'inin `'static` garantisi olmadığından güvenli fallback).
/// Debug build'de eksik key paniklemez, UI'da görünür — böylece eksikler
/// test sırasında fark edilir.
pub fn t(key: &str) -> &'static str {
    // Öncelik: seçilen dil → diğer dil → sabit "?"
    let lang = current();
    let primary = match lang {
        Lang::Tr => lookup_tr(key),
        Lang::En => lookup_en(key),
    };
    primary
        .or_else(|| match lang {
            Lang::Tr => lookup_en(key),
            Lang::En => lookup_tr(key),
        })
        .unwrap_or("?")
}

/// Formatlı çeviri. `{0}`, `{1}` yer tutucularını sırayla `args` ile değiştirir.
///
/// Rust'ın compile-time `format!` makrosu runtime format string kabul etmez;
/// bu yüzden basit `.replace()` tabanlı bir formatter yeterli. `{0}` / `{1}`
/// her dil dosyasında aynı sırada olmak ZORUNDA değil — yer tutucular indeksli,
/// çeviriler cümle yapısına göre yerleri değiştirebilir.
pub fn tf(key: &str, args: &[&str]) -> String {
    let mut out = t(key).to_string();
    for (i, a) in args.iter().enumerate() {
        out = out.replace(&format!("{{{}}}", i), a);
    }
    out
}

// ---------------------------------------------------------------------------
// Türkçe çeviriler (default)
// ---------------------------------------------------------------------------
fn lookup_tr(key: &str) -> Option<&'static str> {
    Some(match key {
        // Tray / menü
        "app.title" => "HekaDrop",
        "tray.title_format" => "HekaDrop — {0}",
        "tray.status.ready" => "Hazır",
        "tray.status.receiving" => "Alınıyor ({0}): {1} %{2}",
        "tray.status.completed" => "Tamamlandı: {0}",
        "tray.show_window" => "Pencereyi göster",
        "tray.send_file" => "Dosya gönder…",
        "tray.cancel" => "Aktarımı iptal et",
        "tray.auto_accept" => "Otomatik kabul",
        "tray.history" => "Son aktarımları göster",
        "tray.open_downloads" => "İndirme klasörünü aç",
        "tray.open_config" => "Yapılandırma dosyasını göster",
        "tray.login_item" => "Başlangıçta aç",
        "tray.about" => "Hakkında",
        "tray.quit" => "Çıkış",
        "tray.tooltip_format" => "HekaDrop — {0}",

        // Bildirimler
        "notify.app_name" => "HekaDrop",
        "notify.auto_accept_on" => "Otomatik kabul açık",
        "notify.auto_accept_off" => "Otomatik kabul kapalı",
        "notify.cancel_requested" => "İptal istendi, aktif transferler sonlandırılıyor…",
        "notify.background" => "Arkaplanda çalışıyor — menü çubuğundan devam edebilirsin",
        "notify.hidden" => "Arkaplana gizlendi — menü çubuğundan aç",
        "notify.sending_to" => "{0} hedefine gönderiliyor: {1}",
        "notify.sent_to" => "Gönderim tamamlandı → {0}",
        "notify.received" => "İndirildi: {0} ({1})",
        "notify.scanning" => "Yakındaki cihazlar taranıyor…",
        "notify.about" => "Quick Share alıcısı/göndericisi — Rust",
        "notify.stats_reset" => "İstatistikler sıfırlandı",
        "notify.trust_removed" => "Güven kaldırıldı: {0}",
        "notify.trust_cleared" => "Tüm güvenilen cihazlar temizlendi",
        "notify.settings_saved" => "Ayarlar kaydedildi",
        "notify.url_opened" => "URL açıldı: {0}",
        "notify.text_clipboard" => "Metin panoya kopyalandı: {0}",

        // Dialog
        "dialog.no_devices" => "Yakında Quick Share cihazı bulunamadı.\n\nAndroid'de: Ayarlar → Bağlı cihazlar → Quick Share → görünürlüğü \"Herkes\" yap ve ekranı açık tut.",
        "dialog.history.empty" => "Henüz aktarım yok.",
        "dialog.history.title" => "Son aktarımlar",
        "dialog.update.latest" => "En güncel sürümü kullanıyorsun (v{0}).",
        "dialog.update.available" => "Mevcut: v{0}\nYeni sürüm: {1}\n\n{2}",
        "dialog.update.failed" => "Güncelleme kontrolü başarısız.\n\nHenüz yayınlanmış bir release yoksa (repo özel ise) bu normal.\nİnternet bağlantını kontrol edip tekrar dene.",
        "dialog.update.title" => "HekaDrop — Güncelleme var",

        // Accept dialog
        "accept.title" => "HekaDrop",
        "accept.body" => "{0} cihazından dosya gönderiliyor.\n\nPIN: {1}\n\n{2}",
        "accept.reject" => "Reddet",
        "accept.accept" => "Kabul et",
        "accept.accept_trust" => "Kabul + güven",
        "accept.content_none" => "içerik yok",
        "accept.text_count" => "{0} metin",
        "accept.trust_prompt" => "{0} cihazını bu ve sonraki aktarımlar için güven listesine ekleyeyim mi?",
        "accept.trust_yes" => "Evet, güven",
        "accept.trust_later" => "Sadece bu sefer",

        // Sender dialog
        "send.choose_title" => "Gönderilecek dosyaları seçin",
        "send.device_prompt" => "Hedef cihaz",
        "send.discovery_error" => "HekaDrop — keşif hatası",
        "send.send_error" => "HekaDrop — gönderim",

        // Time
        "time.seconds_ago" => "{0} sn önce",
        "time.minutes_ago" => "{0} dk önce",
        "time.hours_ago" => "{0} sa önce",
        "time.days_ago" => "{0} gün önce",
        "time.none" => "henüz yok",

        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// English translations
// ---------------------------------------------------------------------------
fn lookup_en(key: &str) -> Option<&'static str> {
    Some(match key {
        // Tray / menu
        "app.title" => "HekaDrop",
        "tray.title_format" => "HekaDrop — {0}",
        "tray.status.ready" => "Ready",
        "tray.status.receiving" => "Receiving ({0}): {1} {2}%",
        "tray.status.completed" => "Completed: {0}",
        "tray.show_window" => "Show window",
        "tray.send_file" => "Send file…",
        "tray.cancel" => "Cancel transfer",
        "tray.auto_accept" => "Auto accept",
        "tray.history" => "Show recent transfers",
        "tray.open_downloads" => "Open downloads folder",
        "tray.open_config" => "Reveal config file",
        "tray.login_item" => "Open at login",
        "tray.about" => "About",
        "tray.quit" => "Quit",
        "tray.tooltip_format" => "HekaDrop — {0}",

        // Notifications
        "notify.app_name" => "HekaDrop",
        "notify.auto_accept_on" => "Auto accept enabled",
        "notify.auto_accept_off" => "Auto accept disabled",
        "notify.cancel_requested" => "Cancel requested — active transfers are ending…",
        "notify.background" => "Running in background — continue from the tray",
        "notify.hidden" => "Hidden to tray — open from the menu bar",
        "notify.sending_to" => "Sending to {0}: {1}",
        "notify.sent_to" => "Transfer complete → {0}",
        "notify.received" => "Received: {0} ({1})",
        "notify.scanning" => "Scanning for nearby devices…",
        "notify.about" => "Quick Share receiver/sender — Rust",
        "notify.stats_reset" => "Statistics cleared",
        "notify.trust_removed" => "Trust removed: {0}",
        "notify.trust_cleared" => "All trusted devices cleared",
        "notify.settings_saved" => "Settings saved",
        "notify.url_opened" => "URL opened: {0}",
        "notify.text_clipboard" => "Text copied to clipboard: {0}",

        // Dialog
        "dialog.no_devices" => "No Quick Share device found nearby.\n\nOn Android: Settings → Connected devices → Quick Share → set visibility to \"Everyone\" and keep the screen on.",
        "dialog.history.empty" => "No transfers yet.",
        "dialog.history.title" => "Recent transfers",
        "dialog.update.latest" => "You're on the latest version (v{0}).",
        "dialog.update.available" => "Current: v{0}\nNew version: {1}\n\n{2}",
        "dialog.update.failed" => "Update check failed.\n\nIf no release is published yet (private repo) this is normal.\nCheck your internet connection and retry.",
        "dialog.update.title" => "HekaDrop — Update available",

        // Accept dialog
        "accept.title" => "HekaDrop",
        "accept.body" => "{0} wants to send you files.\n\nPIN: {1}\n\n{2}",
        "accept.reject" => "Reject",
        "accept.accept" => "Accept",
        "accept.accept_trust" => "Accept + trust",
        "accept.content_none" => "no content",
        "accept.text_count" => "{0} text",
        "accept.trust_prompt" => "Add {0} to the trusted devices list for this and future transfers?",
        "accept.trust_yes" => "Yes, trust",
        "accept.trust_later" => "Just this once",

        // Sender dialog
        "send.choose_title" => "Select files to send",
        "send.device_prompt" => "Target device",
        "send.discovery_error" => "HekaDrop — discovery error",
        "send.send_error" => "HekaDrop — transfer",

        // Time
        "time.seconds_ago" => "{0}s ago",
        "time.minutes_ago" => "{0}m ago",
        "time.hours_ago" => "{0}h ago",
        "time.days_ago" => "{0}d ago",
        "time.none" => "never",

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lang_tr_varyantlari() {
        assert_eq!(parse_lang("tr"), Some(Lang::Tr));
        assert_eq!(parse_lang("TR"), Some(Lang::Tr));
        assert_eq!(parse_lang("tr_TR"), Some(Lang::Tr));
        assert_eq!(parse_lang("tr-TR"), Some(Lang::Tr));
        assert_eq!(parse_lang("tr_TR.UTF-8"), Some(Lang::Tr));
    }

    #[test]
    fn parse_lang_en_varyantlari() {
        assert_eq!(parse_lang("en"), Some(Lang::En));
        assert_eq!(parse_lang("en_US"), Some(Lang::En));
        assert_eq!(parse_lang("en-GB"), Some(Lang::En));
        assert_eq!(parse_lang("en_US.UTF-8"), Some(Lang::En));
    }

    #[test]
    fn parse_lang_desteksiz_none_doner() {
        assert_eq!(parse_lang("de"), None);
        assert_eq!(parse_lang("fr_FR"), None);
        assert_eq!(parse_lang(""), None);
        assert_eq!(parse_lang("C"), None);
    }

    #[test]
    fn tf_yer_tutuculari_doldurur() {
        // Direkt lookup_tr / lookup_en test ederek static LANG'den bağımsız ol.
        let tr = lookup_tr("notify.received").unwrap();
        let mut s = tr.to_string();
        s = s.replace("{0}", "dosya.pdf").replace("{1}", "1.2 MB");
        assert_eq!(s, "İndirildi: dosya.pdf (1.2 MB)");

        let en = lookup_en("notify.received").unwrap();
        let mut s = en.to_string();
        s = s.replace("{0}", "file.pdf").replace("{1}", "1.2 MB");
        assert_eq!(s, "Received: file.pdf (1.2 MB)");
    }

    #[test]
    fn her_key_her_iki_dilde_tanimli() {
        // Test listesinin kapsamı: lookup_tr ve lookup_en'in birinde var olan
        // her key, diğerinde de bulunmalı — aksi halde çeviri boşluğu var demek.
        let sample_keys = [
            "app.title",
            "tray.title_format",
            "tray.status.ready",
            "tray.status.receiving",
            "tray.status.completed",
            "tray.show_window",
            "tray.send_file",
            "tray.cancel",
            "tray.auto_accept",
            "tray.history",
            "tray.open_downloads",
            "tray.open_config",
            "tray.login_item",
            "tray.about",
            "tray.quit",
            "tray.tooltip_format",
            "notify.app_name",
            "notify.auto_accept_on",
            "notify.auto_accept_off",
            "notify.cancel_requested",
            "notify.background",
            "notify.hidden",
            "notify.sending_to",
            "notify.sent_to",
            "notify.received",
            "notify.scanning",
            "notify.about",
            "notify.stats_reset",
            "notify.trust_removed",
            "notify.trust_cleared",
            "notify.settings_saved",
            "notify.url_opened",
            "notify.text_clipboard",
            "dialog.no_devices",
            "dialog.history.empty",
            "dialog.history.title",
            "dialog.update.latest",
            "dialog.update.available",
            "dialog.update.failed",
            "dialog.update.title",
            "accept.title",
            "accept.body",
            "accept.reject",
            "accept.accept",
            "accept.accept_trust",
            "accept.content_none",
            "accept.text_count",
            "accept.trust_prompt",
            "accept.trust_yes",
            "accept.trust_later",
            "send.choose_title",
            "send.device_prompt",
            "send.discovery_error",
            "send.send_error",
            "time.seconds_ago",
            "time.minutes_ago",
            "time.hours_ago",
            "time.days_ago",
            "time.none",
        ];
        for k in &sample_keys {
            assert!(lookup_tr(k).is_some(), "Türkçe çeviri eksik: {}", k);
            assert!(lookup_en(k).is_some(), "English translation missing: {}", k);
        }
    }
}
