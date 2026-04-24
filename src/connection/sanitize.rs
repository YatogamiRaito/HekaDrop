//! Dosya adı ve URL sanitizasyonu — uzak cihaz kontrollü input'tan güvenli yollara.

use crate::error::HekaError;
use crate::state;
use anyhow::Result;
use std::path::PathBuf;

pub(crate) fn unique_downloads_path(name: &str) -> Result<PathBuf> {
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
            return Err(HekaError::PayloadIo(format!("dosya rezerve edilemedi: {}", e)).into());
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
                return Err(HekaError::PayloadIo(format!("dosya rezerve edilemedi: {}", e)).into());
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
pub(crate) fn sanitize_received_name(name: &str) -> String {
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
pub(crate) fn is_safe_url_scheme(url: &str) -> bool {
    let trimmed = url.trim_start();
    let starts = |prefix: &str| {
        trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix)
    };
    starts("http://") || starts("https://")
}

pub(crate) fn split_name(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(idx) if idx > 0 && idx < name.len() - 1 => (&name[..idx], &name[idx + 1..]),
        _ => (name, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
