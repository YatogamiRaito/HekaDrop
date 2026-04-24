//! Log dosyası için PII redaction yardımcıları.
//!
//! HekaDrop log dosyası (`platform::logs_dir()` altında, 3 gün rolling)
//! troubleshooting için paylaşılabilir. Paylaşım senaryosunda kullanıcının
//! ev dizin yapısı, cross-user eşleştirilebilen dosya parmakları (SHA-256)
//! veya URL query token'ları ifşa olmamalı — bu yardımcılar `info!` / `warn!`
//! satırlarında tam path/SHA/URL yerine güvenli kısa formlar üretir.
//!
//! Ne redact EDİLMEZ:
//! - IP adresleri (zaten network debug için gerekli).
//! - `endpoint_id` (ephemeral, proses yeniden başlayınca değişir).
//! - UI bildirimleri (kullanıcı kendi verisini kendi ekranında görür).

use std::path::Path;

/// Tam dosya yolundan yalnızca basename (son segment) döndürür.
///
/// `/home/alice/Belgeler/secret.pdf` → `secret.pdf`.
/// Yol sadece bir bileşense veya parse edilemezse "?" döner.
pub fn path_basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "?".to_string())
}

/// SHA-256'nın ilk 16 hex karakterini (ilk 8 bayt) döndürür. Self-verification
/// için yeterli, cross-user fingerprint için yetersiz. Giriş 16 karakterden
/// kısaysa olduğu gibi döner.
pub fn sha_short(sha_hex: &str) -> &str {
    if sha_hex.len() >= 16 {
        &sha_hex[..16]
    } else {
        sha_hex
    }
}

/// URL'den yalnızca `şema://host` bileşenini döndürür — path + query dahil
/// DEĞİL. Dep-free; manuel `split` ile çalışır.
///
/// `https://example.com/a?token=xyz` → `https://example.com`.
/// Şema veya host parse edilemezse `<unparsable>` döner.
pub fn url_scheme_host(url: &str) -> String {
    let trimmed = url.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some(pair) => pair,
        None => return "<unparsable>".to_string(),
    };
    if scheme.is_empty() {
        return "<unparsable>".to_string();
    }
    // Host bölümü: `userinfo@host:port/path?query` → ilk '/' veya '?' öncesi.
    // `@` varsa userinfo'yu at (login:pass gibi hassas veri içerebilir).
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    if host_port.is_empty() {
        return "<unparsable>".to_string();
    }
    format!("{}://{}", scheme, host_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn redact_path_basename_only() {
        let p = PathBuf::from("/home/user/Belgeler/secret.pdf");
        assert_eq!(path_basename(&p), "secret.pdf");
    }

    #[test]
    fn redact_path_basename_windows_style() {
        // Platform'dan bağımsız — file_name() son OS-segmentini döndürür.
        let p = PathBuf::from("relative/dir/report.xlsx");
        assert_eq!(path_basename(&p), "report.xlsx");
    }

    #[test]
    fn redact_path_basename_fallback_on_root() {
        let p = PathBuf::from("/");
        assert_eq!(path_basename(&p), "?");
    }

    #[test]
    fn redact_sha_short_form() {
        let sha = "a".repeat(64);
        assert_eq!(sha_short(&sha).len(), 16);
        assert_eq!(sha_short(&sha), &"a".repeat(16));
    }

    #[test]
    fn redact_sha_short_passthrough_if_already_short() {
        assert_eq!(sha_short("abc"), "abc");
    }

    #[test]
    fn redact_url_scheme_host_only() {
        assert_eq!(
            url_scheme_host("https://example.com/path?token=abc"),
            "https://example.com"
        );
    }

    #[test]
    fn redact_url_strips_userinfo_and_port_stays() {
        // Kullanıcı adı/şifre düşer; port host'un parçası olarak kalır.
        assert_eq!(
            url_scheme_host("https://user:pass@example.com:8443/x"),
            "https://example.com:8443"
        );
    }

    #[test]
    fn redact_url_with_query_only() {
        assert_eq!(
            url_scheme_host("http://host.local?q=1"),
            "http://host.local"
        );
    }

    #[test]
    fn redact_url_unparsable() {
        assert_eq!(url_scheme_host("not a url"), "<unparsable>");
        assert_eq!(url_scheme_host("://nohost"), "<unparsable>");
    }
}
