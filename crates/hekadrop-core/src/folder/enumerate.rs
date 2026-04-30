//! RFC-0005 §3.4 + §5 — sender-side folder walk + per-file SHA-256
//! pre-compute + `BundleManifest` build helpers.
//!
//! Bu modül **stateless** (no global state, no UI). Sender (`sender.rs::send`)
//! bir directory path için:
//! 1. [`enumerate_folder`] ile recursive walk yapıp `EnumeratedEntry`
//!    listesi alır.
//! 2. [`build_manifest`] ile per-file SHA-256 streaming hash hesaplar +
//!    `BundleManifest` üretir.
//! 3. [`bundle_total_size`] ile `Introduction.size` field'ı için
//!    `52 + manifest_len + sum(file_sizes)` hesabı yapar.
//!
//! Disk I/O policy:
//! - `enumerate_folder` `std::fs` blocking call'ları kullanır; caller
//!   `tokio::task::spawn_blocking` ile sarmalı (yüksek depth/large directory
//!   senaryosunda async runtime'ı bloklar).
//! - `build_manifest` per-file open + `BufReader::read_exact` streaming;
//!   yine blocking, caller `spawn_blocking` ile sarmalı.
//!
//! Limit'ler (RFC-0005 §3.3 + `docs/protocol/folder-payload.md` §3.2 / §5):
//! - [`MAX_FOLDER_DEPTH`] = 32 (path-traversal + filesystem `PATH_MAX` guard)
//! - [`MAX_FOLDER_ENTRIES`] = 10 000 (manifest size + receiver memory cap)

use crate::folder::manifest::{BundleManifest, ManifestEntry, MANIFEST_VERSION};
use crate::folder::sanitize::{sanitize_root_name, PathError};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maksimum nested directory derinliği — RFC-0005 §3.3.
///
/// Sender walk bu değeri aşan branch'i sessizce skip etmek yerine **fail**
/// eder; aksi halde manifest'te eksik entry'ler oluşur ve receiver'da
/// veri kaybına yol açar.
pub const MAX_FOLDER_DEPTH: usize = 32;

/// Maksimum entry sayısı (file + directory) — RFC-0005 §3.3.
///
/// `BundleManifest.total_entries` u32 cap'i ile aynı. 8 MiB manifest cap
/// pratik olarak ~13 000 entry'e dek izin verir; 10 000 receiver memory
/// hijyeni için defansif.
pub const MAX_FOLDER_ENTRIES: usize = 10_000;

/// Sender-side enumerate sonucu — bir manifest entry'sinin disk + manifest
/// metadata kombinasyonu.
///
/// Bu struct manifest'e direkt encode edilmez; [`build_manifest`] bu listeyi
/// `ManifestEntry::{File, Directory}` varyantlarına dönüştürür ve
/// SHA-256'yı per-file hesaplar.
#[derive(Debug, Clone)]
pub struct EnumeratedEntry {
    /// Sender disk üzerindeki absolute path.
    pub absolute_path: PathBuf,
    /// Root-relative POSIX-normalized path (forward-slash). Manifest'te
    /// `entries[*].path` field'ı.
    pub relative_path: String,
    /// Entry tipi (file vs directory).
    pub kind: EntryKind,
    /// Sadece file için anlamlı; directory için 0.
    pub size: u64,
    /// İsteğe bağlı POSIX mode (Unix only). Best-effort.
    pub mode: Option<u32>,
    /// İsteğe bağlı mtime (Unix epoch saniyesi). Best-effort.
    pub mtime: Option<u64>,
}

/// Entry tipi — manifest tagged union'ı (`"file"` / `"directory"`) ile
/// 1:1 eşleşir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

/// Folder walk hata kategorileri.
#[derive(Debug, thiserror::Error)]
pub enum EnumerateError {
    /// `root` mevcut değil veya stat fail.
    #[error("root path okunamadı: {0}")]
    RootStat(#[source] std::io::Error),

    /// `root` directory değil (file/symlink/special).
    #[error("root path bir directory değil")]
    RootNotDirectory,

    /// Walk sırasında directory entry stat fail.
    #[error("directory entry okunamadı: {0}")]
    EntryStat(#[source] std::io::Error),

    /// Walk sırasında `read_dir` fail.
    #[error("read_dir başarısız: {0}")]
    ReadDir(#[source] std::io::Error),

    /// `MAX_FOLDER_DEPTH` aşıldı.
    #[error("derinlik {depth} > {limit}")]
    DepthExceeded { depth: usize, limit: usize },

    /// `MAX_FOLDER_ENTRIES` aşıldı.
    #[error("entry sayısı {count} > {limit}")]
    EntryCountExceeded { count: usize, limit: usize },

    /// `root.file_name()` None (örn. `/` veya `..`) veya sanitize fail.
    #[error("root_name belirlenemedi veya sanitize fail: {0}")]
    RootName(#[source] PathError),

    /// Root içindeki bir entry path'i UTF-8 değil veya path encoding
    /// bozulmuş.
    #[error("path UTF-8 değil veya encoding hatalı")]
    PathEncoding,
}

/// Manifest build hata kategorileri.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// File body open / read fail.
    #[error("file body okunamadı ({path}): {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Root name sanitize fail.
    #[error("root_name sanitize fail: {0}")]
    RootName(#[source] PathError),

    /// Entry sayısı u32'ye sığmıyor (>> `MAX_FOLDER_ENTRIES` de zaten reject).
    #[error("entry sayısı u32 sınırını aşıyor: {0}")]
    EntryCountOverflow(usize),
}

/// Recursive folder walk — file + directory entries döner.
///
/// Davranış (RFC-0005 §3.4 + `docs/protocol/folder-payload.md` §5):
/// - **Symlink:** `symlink_metadata` ile detect; skip + warn log.
/// - **Special file** (block/char/socket/fifo): skip + warn log (Unix-only;
///   Windows'ta `is_file()` / `is_dir()` zaten filtre eder).
/// - **Depth check:** her recursion seviyesinde `MAX_FOLDER_DEPTH` aşılırsa
///   `DepthExceeded` döner.
/// - **Entry count check:** çıktı listesi `MAX_FOLDER_ENTRIES` aşamaz.
/// - **Path encoding:** `OsStr::to_str()` None ise `PathEncoding` döner —
///   manifest UTF-8 zorunlu.
///
/// **Order:** entries deterministic sıralı. Per-directory `read_dir` çıktısı
/// dosya adına göre `sort()` ile sıralanır → cross-platform reproducible
/// manifest (fuzz corpus + receiver byte-exact diff).
///
/// # Errors
///
/// Returns [`EnumerateError`] variant'ları:
/// - `RootStat` — `root` stat I/O hatası
/// - `RootNotDirectory` — `root` symlink veya non-directory
/// - `ReadDir` / `EntryStat` — recursive walk sırasında I/O
/// - `DepthExceeded` — depth > `MAX_FOLDER_DEPTH`
/// - `EntryCountExceeded` — `entries.len()` > `MAX_FOLDER_ENTRIES`
/// - `PathEncoding` — UTF-8'e çevrilemeyen segment
pub fn enumerate_folder(root: &Path) -> Result<Vec<EnumeratedEntry>, EnumerateError> {
    let root_meta = fs::symlink_metadata(root).map_err(EnumerateError::RootStat)?;
    if root_meta.file_type().is_symlink() {
        return Err(EnumerateError::RootNotDirectory);
    }
    if !root_meta.is_dir() {
        return Err(EnumerateError::RootNotDirectory);
    }

    let mut out: Vec<EnumeratedEntry> = Vec::new();
    walk_directory(root, root, 0, &mut out)?;
    Ok(out)
}

fn walk_directory(
    root: &Path,
    current: &Path,
    depth: usize,
    out: &mut Vec<EnumeratedEntry>,
) -> Result<(), EnumerateError> {
    if depth > MAX_FOLDER_DEPTH {
        return Err(EnumerateError::DepthExceeded {
            depth,
            limit: MAX_FOLDER_DEPTH,
        });
    }

    let read = fs::read_dir(current).map_err(EnumerateError::ReadDir)?;
    let mut child_paths: Vec<PathBuf> = Vec::new();
    for entry in read {
        let entry = entry.map_err(EnumerateError::ReadDir)?;
        child_paths.push(entry.path());
    }
    // Deterministic order — cross-platform manifest reproducibility.
    child_paths.sort();

    for child in child_paths {
        // INVARIANT (CLAUDE.md I-5): entry count peer-controlled değil ama
        // directory'de milyonlarca file olabilir → defansif cap.
        if out.len() >= MAX_FOLDER_ENTRIES {
            return Err(EnumerateError::EntryCountExceeded {
                count: out.len() + 1,
                limit: MAX_FOLDER_ENTRIES,
            });
        }

        let meta = fs::symlink_metadata(&child).map_err(EnumerateError::EntryStat)?;
        let ft = meta.file_type();

        if ft.is_symlink() {
            tracing::warn!("[sender] folder walk: symlink skip: {}", child.display());
            continue;
        }

        // Special files (Unix): block/char/socket/fifo — `is_file()` ve
        // `is_dir()` ikisi de false döner.
        if !ft.is_file() && !ft.is_dir() {
            tracing::warn!(
                "[sender] folder walk: special file skip: {}",
                child.display()
            );
            continue;
        }

        let relative_path = relative_to_root(root, &child)?;
        let mode = extract_mode(&meta);
        let mtime = extract_mtime(&meta);

        if ft.is_dir() {
            out.push(EnumeratedEntry {
                absolute_path: child.clone(),
                relative_path,
                kind: EntryKind::Directory,
                size: 0,
                mode,
                mtime,
            });
            walk_directory(root, &child, depth + 1, out)?;
        } else {
            // is_file() == true
            out.push(EnumeratedEntry {
                absolute_path: child,
                relative_path,
                kind: EntryKind::File,
                size: meta.len(),
                mode,
                mtime,
            });
        }
    }

    Ok(())
}

/// `child` path'ini `root` altına göre relative POSIX-normalize string'e
/// çevir.
fn relative_to_root(root: &Path, child: &Path) -> Result<String, EnumerateError> {
    // INVARIANT (CLAUDE.md I-3): `StripPrefixError` zero-sized marker — taşıyacak
    // ek context yok; `EnumerateError::PathEncoding` canonical reporting yeri.
    let Ok(rel) = child.strip_prefix(root) else {
        return Err(EnumerateError::PathEncoding);
    };
    let mut parts: Vec<String> = Vec::new();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(s) => {
                let s_str = s.to_str().ok_or(EnumerateError::PathEncoding)?;
                // RFC-0005 §5.1: Windows backslash → forward slash. Component
                // bazında walk ettiğimiz için zaten OS separator'ı atlanmış
                // oluyor; component value'su raw segment string.
                parts.push(s_str.to_owned());
            }
            // Root/parent/curdir component beklenmiyor (strip_prefix sonrası);
            // defansif olarak fail.
            _ => return Err(EnumerateError::PathEncoding),
        }
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn extract_mode(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode())
}

#[cfg(not(unix))]
fn extract_mode(_meta: &fs::Metadata) -> Option<u32> {
    None
}

fn extract_mtime(meta: &fs::Metadata) -> Option<u64> {
    let mt = meta.modified().ok()?;
    let dur = mt.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_secs())
}

/// Per-file SHA-256 streaming hash + `BundleManifest` build.
///
/// Çağıran (sender) `enumerate_folder` çıktısını ve aynı root path'i geçer.
/// `root.file_name()` `BundleManifest.root_name` olarak kullanılır;
/// sanitize edildikten sonra atanır.
///
/// **Performans notu:** her file için `BufReader` + 64 KiB chunk. 1 GB
/// folder ~10–15 sn (host disk hızına bağlı). Async runtime'ı bloklamamak
/// için caller `spawn_blocking` ile sarmalı.
///
/// # Errors
///
/// Returns [`BuildError`] variant'ları:
/// - `RootName` — `root.file_name()` sanitize fail
/// - `EntryCountOverflow` — `entries.len() > u32::MAX`
/// - `FileRead` — bir entry dosyası açılamadı / okunamadı (SHA-256 streaming)
pub fn build_manifest(
    root: &Path,
    entries: &[EnumeratedEntry],
) -> Result<BundleManifest, BuildError> {
    let root_name_raw = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("klasor");
    let root_name = sanitize_root_name(root_name_raw).map_err(BuildError::RootName)?;

    // INVARIANT (CLAUDE.md I-3): `TryFromIntError` zero-sized marker; canonical
    // reporting `BuildError::EntryCountOverflow.0` field.
    let Ok(total_entries) = u32::try_from(entries.len()) else {
        return Err(BuildError::EntryCountOverflow(entries.len()));
    };

    let mut manifest_entries: Vec<ManifestEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry.kind {
            EntryKind::Directory => {
                manifest_entries.push(ManifestEntry::Directory {
                    path: entry.relative_path.clone(),
                    mode: entry.mode,
                    mtime: entry.mtime,
                });
            }
            EntryKind::File => {
                let sha256_hex =
                    file_sha256_hex(&entry.absolute_path).map_err(|e| BuildError::FileRead {
                        path: entry.relative_path.clone(),
                        source: e,
                    })?;
                manifest_entries.push(ManifestEntry::File {
                    path: entry.relative_path.clone(),
                    size: entry.size,
                    sha256: sha256_hex,
                    mode: entry.mode,
                    mtime: entry.mtime,
                });
            }
        }
    }

    Ok(BundleManifest {
        version: MANIFEST_VERSION,
        root_name,
        total_entries,
        entries: manifest_entries,
        // RFC3339 UTC; manifest schema doc §3.1.
        created_utc: <chrono::DateTime<Utc>>::from(SystemTime::now()),
    })
}

/// Streaming SHA-256 hash → 64-char lowercase hex.
fn file_sha256_hex(path: &Path) -> std::io::Result<String> {
    let f = fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// `HEKABUND` toplam bundle byte boyutu (header + manifest + `concat_data` +
/// trailer). `Introduction.FileMetadata.size` field'ı bunu kullanır.
///
/// Hesap: `16 (header) + manifest_json.len() + sum(file_sizes) + 32 (trailer)`.
///
/// Overflow defansif: `file_sizes` toplamı u64'a sığmazsa `None` döner —
/// caller bundle'ı reddedip flatten fallback'e düşmeli (pratikte erişilemez,
/// 16 EiB folder).
#[must_use]
pub fn bundle_total_size(manifest_json_len: usize, entries: &[EnumeratedEntry]) -> Option<u64> {
    use crate::folder::bundle::{HEADER_LEN, TRAILER_LEN};

    let mut total: u64 = HEADER_LEN as u64;
    total = total.checked_add(u64::try_from(manifest_json_len).ok()?)?;
    for entry in entries {
        if entry.kind == EntryKind::File {
            total = total.checked_add(entry.size)?;
        }
    }
    total = total.checked_add(TRAILER_LEN as u64)?;
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_file(dir: &Path, rel: &str, body: &[u8]) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&full).unwrap();
        f.write_all(body).unwrap();
    }

    #[test]
    fn enumerate_root_must_be_directory() {
        let tmp = tempdir().unwrap();
        let file = tmp.path().join("not_a_dir.txt");
        fs::write(&file, b"x").unwrap();
        let r = enumerate_folder(&file);
        assert!(matches!(r, Err(EnumerateError::RootNotDirectory)));
    }

    #[test]
    fn enumerate_simple_two_files() {
        let tmp = tempdir().unwrap();
        write_file(tmp.path(), "a.txt", b"alpha");
        write_file(tmp.path(), "b.txt", b"beta_payload");

        let entries = enumerate_folder(tmp.path()).unwrap();
        let files: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        assert_eq!(files.len(), 2);
        // Deterministic order: a.txt before b.txt.
        assert_eq!(files[0].relative_path, "a.txt");
        assert_eq!(files[0].size, 5);
        assert_eq!(files[1].relative_path, "b.txt");
        assert_eq!(files[1].size, 12);
    }

    #[test]
    fn enumerate_nested_directory_creates_directory_entry() {
        let tmp = tempdir().unwrap();
        write_file(tmp.path(), "sub/inner.txt", b"abc");
        let entries = enumerate_folder(tmp.path()).unwrap();
        // Beklenen: directory "sub" + file "sub/inner.txt"
        let dirs: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Directory)
            .collect();
        let files: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].relative_path, "sub");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].relative_path, "sub/inner.txt");
    }

    #[test]
    fn enumerate_depth_limit_enforced() {
        let tmp = tempdir().unwrap();
        // 33-deep nested dir → MAX_FOLDER_DEPTH (32) aşılır.
        let mut path = tmp.path().to_path_buf();
        for i in 0..33 {
            path = path.join(format!("d{i}"));
        }
        fs::create_dir_all(&path).unwrap();
        let r = enumerate_folder(tmp.path());
        assert!(
            matches!(r, Err(EnumerateError::DepthExceeded { .. })),
            "got {r:?}"
        );
    }

    #[test]
    fn build_manifest_per_file_sha256_correct() {
        let tmp = tempdir().unwrap();
        write_file(tmp.path(), "a.txt", b"hello");
        write_file(tmp.path(), "b.txt", b"world");
        let entries = enumerate_folder(tmp.path()).unwrap();
        let manifest = build_manifest(tmp.path(), &entries).unwrap();

        // root_name = tempdir leaf name (random-ish).
        assert!(!manifest.root_name.is_empty());
        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.total_entries as usize, entries.len());

        // Per-file SHA-256 — bağımsız hesapla, manifest ile karşılaştır.
        for entry in &manifest.entries {
            if let ManifestEntry::File { path, sha256, .. } = entry {
                let expected = if path == "a.txt" {
                    let mut h = Sha256::new();
                    h.update(b"hello");
                    hex_lower(&h.finalize())
                } else if path == "b.txt" {
                    let mut h = Sha256::new();
                    h.update(b"world");
                    hex_lower(&h.finalize())
                } else {
                    panic!("beklenmeyen path: {path}");
                };
                assert_eq!(sha256, &expected);
            }
        }
        manifest.validate().unwrap();
    }

    #[test]
    fn bundle_total_size_calculation_basic() {
        // 16 header + manifest_len + (5 + 12) + 32 trailer
        let tmp = tempdir().unwrap();
        write_file(tmp.path(), "a.txt", b"hello");
        write_file(tmp.path(), "b.txt", b"twelve_bytes");
        let entries = enumerate_folder(tmp.path()).unwrap();
        let manifest_json = b"{\"placeholder\":\"100bytes\"}";
        let total = bundle_total_size(manifest_json.len(), &entries).unwrap();
        // Sadece file size'ları toplanır (5 + 12 = 17), directory 0 katkı.
        let expected = 16u64 + manifest_json.len() as u64 + 5 + 12 + 32;
        assert_eq!(total, expected);
    }

    #[test]
    fn enumerate_entry_count_limit_enforced() {
        // MAX_FOLDER_ENTRIES + 1 (10001) file create — uzun ama walk hızlı.
        let tmp = tempdir().unwrap();
        for i in 0..=MAX_FOLDER_ENTRIES {
            // Per-loop file create — flat dir; depth=1.
            let p = tmp.path().join(format!("f{i:05}.txt"));
            fs::write(&p, b"x").unwrap();
        }
        let r = enumerate_folder(tmp.path());
        assert!(
            matches!(r, Err(EnumerateError::EntryCountExceeded { .. })),
            "got {r:?}"
        );
    }
}
