//! RFC-0005 §5 — `HEKABUND` per-segment path sanitization.
//!
//! Folder bundle her bir manifest entry'sinin `path` alanı için **per-segment**
//! sanitize kuralları uygular. Bu bestaande `sanitize_received_name`
//! (basename-only) helper'ından farklıdır:
//!
//! - basename-only helper `..` segmentini sessizce `"dosya"` olarak yeniden
//!   yazar — single-file akışında zararsız ama multi-segment context'te
//!   silent path mutation entries arası collision yaratabilir.
//! - bu modül `..` görür görmez **tüm bundle'ı reject** eder; defensive
//!   anti-traversal posture.
//!
//! Wire-byte-exact spec: `docs/protocol/folder-payload.md` §5.

/// Per-segment path sanitize sonucu döner ya da hata fırlatır.
///
/// Kurallar (`docs/protocol/folder-payload.md` §5):
/// - `\` (Windows separator) → reject (sender POSIX-normalize etmeliydi)
/// - `\0` (NUL byte) → reject
/// - `..` segment → reject (path traversal)
/// - `.` segment → skip
/// - boş segment (consecutive `/`, leading `/`, trailing `/`) → skip
///   (örn. `a//b` → `["a", "b"]`, `a/b/` → `["a", "b"]`); `.` segment ile
///   aynı politikayla normalize, reject değil — POSIX path normalize
///   davranışı.
/// - depth (sanitize sonrası segment sayısı) > 32 → reject
/// - sanitize sonrası boş → reject
///
/// Bu helper **basename-only** karakter sanitize'i (control char, Windows
/// reserved name, length cap) burada UYGULAMAZ — yalnız structural traversal
/// guard. PR-D'de extract pipeline her segment'i ayrıca
/// `sanitize_received_name` zinciriyle filtre eder; o katman karakter
/// kontrolünü yapar.
///
/// # Errors
///
/// Returns [`PathError`] variant'ları:
/// - `BackslashSeparator` — `\` karakter
/// - `NullByte` — `\0` byte
/// - `Traversal` — `..` segment
/// - `DepthExceeded` — segment sayısı > `MAX_DEPTH`
/// - `Empty` — sanitize sonrası segment kalmadı
pub fn sanitize_received_relative_path(raw: &str) -> Result<Vec<String>, PathError> {
    if raw.contains('\\') {
        return Err(PathError::BackslashSeparator);
    }
    if raw.contains('\0') {
        return Err(PathError::NullByte);
    }

    let mut out: Vec<String> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(PathError::Traversal),
            other => out.push(other.to_owned()),
        }
    }

    if out.len() > MAX_DEPTH {
        return Err(PathError::DepthExceeded(out.len()));
    }
    if out.is_empty() {
        return Err(PathError::Empty);
    }

    Ok(out)
}

/// `root_name` için sanitize: tek segment, `/` ve `\` yasak.
///
/// `BundleManifest.root_name` receiver'ın UI'da göreceği klasör ismi
/// (`~/Downloads/<root_name>/`). Slash ya da backslash içermesi sender bug'ı
/// veya hostile input'tur — reject.
///
/// # Errors
///
/// Returns [`PathError`] variant'ları:
/// - `Empty` — boş string
/// - `BackslashSeparator` — `/` veya `\` karakter
/// - `NullByte` — `\0` byte
/// - `Traversal` — `.` veya `..` exact match
pub fn sanitize_root_name(raw: &str) -> Result<String, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }
    if raw.contains('/') || raw.contains('\\') {
        return Err(PathError::BackslashSeparator);
    }
    if raw.contains('\0') {
        return Err(PathError::NullByte);
    }
    if raw == "." || raw == ".." {
        return Err(PathError::Traversal);
    }
    Ok(raw.to_owned())
}

/// Maksimum nested directory derinliği (RFC-0005 §3.3 / §5).
pub const MAX_DEPTH: usize = 32;

/// Path sanitize hata kategorileri.
///
/// `PartialEq + Eq` test ergonomi için; receiver UI katmanında i18n key'e
/// map'lenir.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    /// `..` segment — path traversal saldırısı varsayımı.
    #[error("path traversal `..` segment")]
    Traversal,

    /// `\` karakter — Windows separator wire'da yasak (POSIX-only).
    #[error("Windows separator `\\` in path")]
    BackslashSeparator,

    /// `\0` NUL byte — UNIX path API'leri için truncation riski.
    #[error("null byte in path")]
    NullByte,

    /// Segment sayısı `MAX_DEPTH` üstünde.
    #[error("depth {0} exceeds limit 32")]
    DepthExceeded(usize),

    /// Sanitize sonrası segment kalmamış (`""`, `"./"`, `"/"` vs).
    #[error("path empty after sanitize")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_simple_path_ok() {
        let segs = sanitize_received_relative_path("a/b/c.txt").unwrap();
        assert_eq!(segs, vec!["a", "b", "c.txt"]);
    }

    #[test]
    fn sanitize_single_segment_ok() {
        let segs = sanitize_received_relative_path("file.txt").unwrap();
        assert_eq!(segs, vec!["file.txt"]);
    }

    #[test]
    fn sanitize_traversal_rejected_simple() {
        assert_eq!(
            sanitize_received_relative_path(".."),
            Err(PathError::Traversal)
        );
    }

    #[test]
    fn sanitize_traversal_rejected_leading() {
        assert_eq!(
            sanitize_received_relative_path("../escape"),
            Err(PathError::Traversal)
        );
    }

    #[test]
    fn sanitize_traversal_rejected_middle() {
        assert_eq!(
            sanitize_received_relative_path("a/../b"),
            Err(PathError::Traversal)
        );
    }

    #[test]
    fn sanitize_traversal_rejected_trailing() {
        assert_eq!(
            sanitize_received_relative_path("a/.."),
            Err(PathError::Traversal)
        );
    }

    #[test]
    fn sanitize_traversal_corpus_extended() {
        // RFC-0005 §5 + `docs/protocol/folder-payload.md` §10 traversal
        // corpus — fuzz seed'i olarak da PR-D harness'inde kullanılacak.
        let cases = [
            "..",
            "../",
            "a/..",
            "a/../b",
            "../../etc/passwd",
            "x/y/../../z",
        ];
        for raw in cases {
            assert_eq!(
                sanitize_received_relative_path(raw),
                Err(PathError::Traversal),
                "expected Traversal for {raw:?}"
            );
        }
    }

    #[test]
    fn sanitize_dot_segments_skipped() {
        let segs = sanitize_received_relative_path("a/./b").unwrap();
        assert_eq!(segs, vec!["a", "b"]);
    }

    #[test]
    fn sanitize_consecutive_slashes_collapsed() {
        let segs = sanitize_received_relative_path("a//b").unwrap();
        assert_eq!(segs, vec!["a", "b"]);
    }

    #[test]
    fn sanitize_multiple_consecutive_slashes_collapsed() {
        // `a///b` ve `a////b/c` — boş segment skip politikası tüm consecutive
        // separator senaryolarında deterministik (Gemini PR #143 yorumu — empty
        // segment policy dokümante).
        assert_eq!(
            sanitize_received_relative_path("a///b").unwrap(),
            vec!["a", "b"]
        );
        assert_eq!(
            sanitize_received_relative_path("a////b/c").unwrap(),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn sanitize_trailing_slash_skipped() {
        let segs = sanitize_received_relative_path("a/b/").unwrap();
        assert_eq!(segs, vec!["a", "b"]);
    }

    #[test]
    fn sanitize_leading_slash_skipped() {
        let segs = sanitize_received_relative_path("/a/b").unwrap();
        assert_eq!(segs, vec!["a", "b"]);
    }

    #[test]
    fn sanitize_backslash_rejected() {
        assert_eq!(
            sanitize_received_relative_path("a\\b"),
            Err(PathError::BackslashSeparator)
        );
    }

    #[test]
    fn sanitize_backslash_traversal_rejected() {
        // `..\\` saldırısı (Windows-shell-style traversal) — backslash check
        // önce vurur, ama her iki şekilde de reject; kategori önemli değil
        // burada sadece reject kesin.
        let r = sanitize_received_relative_path("..\\escape");
        assert!(matches!(
            r,
            Err(PathError::BackslashSeparator | PathError::Traversal)
        ));
    }

    #[test]
    fn sanitize_null_byte_rejected() {
        assert_eq!(
            sanitize_received_relative_path("a\0b"),
            Err(PathError::NullByte)
        );
    }

    #[test]
    fn sanitize_depth_limit_enforced() {
        // 33 segment derinliği — limit 32 üstü reject.
        let raw = (0..33)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            sanitize_received_relative_path(&raw),
            Err(PathError::DepthExceeded(33))
        );
    }

    #[test]
    fn sanitize_depth_limit_boundary_ok() {
        // Tam 32 segment — sınırda kabul.
        let raw = (0..32)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let segs = sanitize_received_relative_path(&raw).unwrap();
        assert_eq!(segs.len(), 32);
    }

    #[test]
    fn sanitize_empty_input_rejected() {
        assert_eq!(sanitize_received_relative_path(""), Err(PathError::Empty));
    }

    #[test]
    fn sanitize_only_dot_rejected() {
        assert_eq!(sanitize_received_relative_path("./"), Err(PathError::Empty));
        assert_eq!(sanitize_received_relative_path("."), Err(PathError::Empty));
    }

    #[test]
    fn sanitize_only_slashes_rejected() {
        assert_eq!(
            sanitize_received_relative_path("///"),
            Err(PathError::Empty)
        );
    }

    #[test]
    fn sanitize_root_name_simple() {
        assert_eq!(sanitize_root_name("docs").unwrap(), "docs");
    }

    #[test]
    fn sanitize_root_name_separator_rejected() {
        assert_eq!(
            sanitize_root_name("a/b"),
            Err(PathError::BackslashSeparator)
        );
        assert_eq!(
            sanitize_root_name("a\\b"),
            Err(PathError::BackslashSeparator)
        );
    }

    #[test]
    fn sanitize_root_name_empty_rejected() {
        assert_eq!(sanitize_root_name(""), Err(PathError::Empty));
    }

    #[test]
    fn sanitize_root_name_dot_rejected() {
        assert_eq!(sanitize_root_name("."), Err(PathError::Traversal));
        assert_eq!(sanitize_root_name(".."), Err(PathError::Traversal));
    }

    #[test]
    fn sanitize_root_name_null_rejected() {
        assert_eq!(sanitize_root_name("a\0b"), Err(PathError::NullByte));
    }
}
