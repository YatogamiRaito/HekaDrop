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
//! Bilinmeyen key'ler ve eksik çeviriler **key string'inin kendisi** olarak döner
//! — böylece "tray.status.ready" gibi bir ifade UI'da gözükür ve eksik çeviri
//! gözden kaçmaz. `t()`/`tf()` `&'static str` key alır (çağrılar genelde
//! literal), fallback lifetime problemsiz çalışır.

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

/// Key → çeviri. Sıra: seçilen dil → diğer dil → key'in kendisi.
///
/// `key` `&'static str` — çağrı siteleri literal olduğundan (`t("tray.xxx")`)
/// bu kısıt sorun değil ve fallback olarak key'i dönmeyi güvenli kılar.
/// Eksik çeviri varsa UI'da key string'i görünür, dev fark eder.
pub fn t(key: &'static str) -> &'static str {
    let lang = current();
    match lang {
        Lang::Tr => lookup_tr(key).or_else(|| lookup_en(key)).unwrap_or(key),
        Lang::En => lookup_en(key).or_else(|| lookup_tr(key)).unwrap_or(key),
    }
}

/// Formatlı çeviri. `{0}`, `{1}` yer tutucularını sırayla `args` ile değiştirir.
///
/// Rust'ın compile-time `format!` makrosu runtime format string kabul etmez;
/// bu yüzden template'i tek-geçişli kendimiz parse ediyoruz. Çoklu `.replace()`
/// çağrısı "double-replace" bug'ına açık olurdu (args içinde `{N}` varsa
/// sonraki iterasyonda tekrar değiştiriliyordu) — single-pass parser bundan
/// bağışık.
///
/// Placeholder olmayan `{` karakterleri literal bırakılır (kullanıcıya
/// gösterilen metinde `{X}` geçmesi tipik değil ama güvenli).
pub fn tf(key: &'static str, args: &[&str]) -> String {
    apply_args(t(key), args)
}

/// Template stringinde `{N}` yer tutucularını args ile doldurur (single-pass).
/// Public `tf()`'nin test edilebilir yan yüzü — `current()` OnceLock'una
/// bağımlı değil, saf deterministik fonksiyon.
pub(crate) fn apply_args(template: &str, args: &[&str]) -> String {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(bytes.len() + 32);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // `{N}` olup olmadığına bak (N = 1+ ASCII digit, sonra `}`).
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b'}' {
                // Geçerli `{N}` — index'i parse et ve arg'ı yaz.
                if let Ok(idx) = template[start..j].parse::<usize>() {
                    if let Some(arg) = args.get(idx) {
                        out.push_str(arg);
                        i = j + 1;
                        continue;
                    }
                }
            }
            // Geçersiz/indeks aralık dışı — `{` karakterini literal bırak.
            out.push('{');
            i += 1;
        } else {
            // Bir sonraki `{`'e kadar toplu kopyala (hızlı path).
            let end = template[i..]
                .find('{')
                .map(|p| i + p)
                .unwrap_or(bytes.len());
            out.push_str(&template[i..end]);
            i = end;
        }
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
        "notify.transfer_cancelled" => "Aktarım iptal edildi",
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
        "pick.download_folder" => "İndirme klasörünü seçin",
        "common.send" => "Gönder",
        "common.cancel" => "İptal",

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
        "notify.transfer_cancelled" => "Transfer cancelled",
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
        "pick.download_folder" => "Select download folder",
        "common.send" => "Send",
        "common.cancel" => "Cancel",

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
    fn apply_args_basit_iki_yer_tutucu() {
        // Deterministik test — `current()` OnceLock'una bağlı değil.
        assert_eq!(
            apply_args("İndirildi: {0} ({1})", &["dosya.pdf", "1.2 MB"]),
            "İndirildi: dosya.pdf (1.2 MB)"
        );
    }

    #[test]
    fn apply_args_yer_degistirme_baglantisiz() {
        // Placeholders her dilde aynı sırada olmak zorunda değil.
        assert_eq!(
            apply_args("{1} to {0}", &["alpha", "beta"]),
            "beta to alpha"
        );
    }

    #[test]
    fn apply_args_double_replace_bug_olmuyor() {
        // Klasik bug senaryosu: ilk arg, sonraki placeholder'ı içeriyor.
        // Çoklu .replace() ile "{1}" tekrar değiştirilirdi. Single-pass
        // parser'da arg içeriği template olarak yorumlanmaz.
        assert_eq!(apply_args("{0} and {1}", &["{1}", "val"]), "{1} and val");
        assert_eq!(apply_args("{0} / {1}", &["{0}", "x"]), "{0} / x");
    }

    #[test]
    fn apply_args_indeks_disi_literal_kalir() {
        // args'ta olmayan index → `{5}` literal olarak yazılır.
        assert_eq!(apply_args("hi {5}", &["a"]), "hi {5}");
    }

    #[test]
    fn apply_args_bracket_literal_korunur() {
        // Geçersiz placeholder ({} boş, {ab} non-digit) literal kalır.
        assert_eq!(apply_args("{} and {ab}", &["x"]), "{} and {ab}");
    }

    #[test]
    fn apply_args_bos_template_bos_doner() {
        assert_eq!(apply_args("", &["x"]), "");
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
            "notify.transfer_cancelled",
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
            "pick.download_folder",
            "common.send",
            "common.cancel",
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
