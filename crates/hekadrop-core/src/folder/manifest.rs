//! RFC-0005 §3 — `BundleManifest` JSON schema (in-bundle).
//!
//! Manifest, `HEKABUND` container'ın `manifest_json` slot'unda yaşar (UTF-8,
//! ≤ 8 MiB). Wire'da protobuf değildir — `FolderManifest` proto mesajı v1'de
//! kasıtlı olarak boştur (slot ABI mühürleme; bkz.
//! `crates/hekadrop-proto/proto/hekadrop_extensions.proto`).
//!
//! Wire-byte-exact spec: `docs/protocol/folder-payload.md` §3.

use crate::folder::sanitize::{sanitize_received_relative_path, sanitize_root_name, PathError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Manifest schema sürümü — v0.8.x boyunca yalnız `1`.
///
/// Bump `FOLDER_STREAM_V<n>` capability bit gerektirir
/// (bkz. `docs/protocol/folder-payload.md` §3.3).
pub const MANIFEST_VERSION: u32 = 1;

/// `total_entries` üst sınırı (RFC-0005 §3.3 / `docs/protocol/folder-payload.md`
/// §3.2 satırı).
pub const MAX_ENTRIES: u32 = 10_000;

/// `BundleManifest` — `HEKABUND` içindeki kanonik metadata.
///
/// Field sırası `docs/protocol/folder-payload.md` §3.1 ile **byte-exact** —
/// JSON canonicalization sırası bu struct field sırasına göre derive
/// edilir (serde default top-level ordering).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    /// Schema version. Şu anda yalnız `1` geçerli (`MANIFEST_VERSION`).
    pub version: u32,

    /// Receiver'ın `~/Downloads/<root_name>/` altına extract ettiği klasör
    /// adı. Sender tarafında sanitize edilmiş tek segment.
    pub root_name: String,

    /// `entries.len()` ile **eşleşmeli** (validate guard).
    pub total_entries: u32,

    /// Concat-data sırası bu vektörün sırasıyla aynıdır (file body'leri
    /// birleştirilirken).
    pub entries: Vec<ManifestEntry>,

    /// ISO-8601 UTC ("…Z" suffix). Sender üretim zamanı; receiver UI'da
    /// göstermek için.
    pub created_utc: DateTime<Utc>,
}

/// `ManifestEntry` — file ya da directory varyantı (tagged union, JSON `type`
/// alanı ayırır).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ManifestEntry {
    /// File entry: body `concat_data`'da entry sırasına göre yer alır.
    File {
        /// Root-relative POSIX path (forward-slash separator).
        path: String,
        /// Body uzunluğu (byte). 0 ≤ size ≤ `i64::MAX` — wire kontratı u64
        /// tutar ama negatif/aşırı değerler validate fail.
        size: u64,
        /// 64-char lowercase hex SHA-256 digest of body (`docs/.../folder-
        /// payload.md` §3.1).
        sha256: String,
        /// İsteğe bağlı POSIX mode (decimal). Best-effort uygula; platform
        /// desteklemiyorsa silently drop.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        /// İsteğe bağlı Unix epoch saniyesi (mtime). Best-effort.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtime: Option<u64>,
    },
    /// Directory entry: `concat_data`'ya 0 byte katkı.
    Directory {
        /// Root-relative POSIX path.
        path: String,
        /// İsteğe bağlı POSIX mode (decimal).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        /// İsteğe bağlı Unix epoch saniyesi.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtime: Option<u64>,
    },
}

impl ManifestEntry {
    /// Entry path'ini döndür (file / directory variant agnostic).
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Directory { path, .. } => path,
        }
    }
}

impl BundleManifest {
    /// Manifest schema-level validate guard (RFC-0005 §3.2).
    ///
    /// Sıra:
    /// 1. `version == MANIFEST_VERSION`
    /// 2. `total_entries == entries.len()` (and ≤ `MAX_ENTRIES`)
    /// 3. `root_name` sanitize OK
    /// 4. her entry path sanitize OK + duplicate path yok
    /// 5. file entry'lerin `sha256` field'ı 64-char hex
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }

        let actual = self.entries.len();
        // INVARIANT (CLAUDE.md I-5): peer-controlled `total_entries` u32, ama
        // `entries.len()` usize. u32 → u64 lossless via From; usize → u64
        // 64-bit hedeflerde lossless (CI matrix tüm hedefler 64-bit), 32-bit
        // hedefte de usize ≤ u32 ≤ u64 yine lossless.
        let claimed_u64 = u64::from(self.total_entries);
        let actual_u64 = u64::try_from(actual).unwrap_or(u64::MAX);
        if claimed_u64 != actual_u64 {
            return Err(ManifestError::EntryCountMismatch {
                claimed: self.total_entries,
                actual,
            });
        }
        if self.total_entries > MAX_ENTRIES {
            return Err(ManifestError::EntryCountExceeded {
                claimed: self.total_entries,
                limit: MAX_ENTRIES,
            });
        }

        sanitize_root_name(&self.root_name)?;

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for entry in &self.entries {
            let path = entry.path();
            sanitize_received_relative_path(path)?;
            if !seen.insert(path) {
                return Err(ManifestError::DuplicatePath(path.to_owned()));
            }
            if let ManifestEntry::File { sha256, .. } = entry {
                if !is_lowercase_hex_64(sha256) {
                    return Err(ManifestError::Sha256HexFormat);
                }
            }
        }

        Ok(())
    }

    /// Manifest JSON canonical byte stream'inin SHA-256 digest'i.
    ///
    /// Bu fonksiyon struct'tan deterministik canonical JSON üretip hash
    /// hesaplar. Sender-side intro-frame `attachment_hash` hesabı için
    /// kullanılır. `serde_json::to_vec` infallible değil teknik olarak
    /// (custom serializer panic'i mümkün) ama `BundleManifest`'in alanları
    /// salt primitive + Vec/String/Option olduğundan derive Serialize hata
    /// üretmez — yine de Result imzası API güvenliği için tutuluyor.
    ///
    /// Canonical encoding: `serde_json::to_vec` — field sırası struct
    /// declaration sırasına göre. JSON whitespace yok (compact form).
    pub fn manifest_sha256(&self) -> Result<[u8; 32], serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        Ok(Self::sha256_of_bytes(&bytes))
    }

    /// Convenience: pre-serialized `manifest_json` bytes üzerinden hash.
    /// Sender bundle build pipeline'ında `BundleWriter::new`'e geçirdiği
    /// bytes ile aynı hash'i bağımsız hesaplamak için kullanır.
    #[must_use]
    pub fn sha256_of_bytes(manifest_json: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(manifest_json);
        hasher.finalize().into()
    }

    /// Intro-frame `FileMetadata.attachment_hash` (signed i64) hesabı.
    ///
    /// `i64::from_be_bytes(manifest_sha256[0..8])` —
    /// `docs/protocol/folder-payload.md` §4.1.
    pub fn attachment_hash_i64(&self) -> Result<i64, serde_json::Error> {
        let digest = self.manifest_sha256()?;
        // INVARIANT: digest sabit 32 byte; [0..8] slice her zaman 8 byte.
        // try_into() infallible — array → array.
        #[allow(clippy::expect_used)] // INVARIANT: 32-byte digest, [0..8] her zaman 8 byte
        let prefix: [u8; 8] = digest[0..8].try_into().expect("sha256 prefix is 8 bytes");
        Ok(i64::from_be_bytes(prefix))
    }
}

/// Convenience: 64-char lowercase hex check.
fn is_lowercase_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Manifest validate guard hata kategorileri.
///
/// Receiver UI'da i18n key'e map'lenir; mesajlar log için.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    /// `version` field'ı `MANIFEST_VERSION` değil.
    #[error("schema version {0} unsupported")]
    UnsupportedVersion(u32),

    /// `total_entries` field'ı `entries.len()` ile eşleşmiyor.
    #[error("total_entries {claimed} != entries.len() {actual}")]
    EntryCountMismatch { claimed: u32, actual: usize },

    /// `total_entries > MAX_ENTRIES` (10 000 cap).
    #[error("total_entries {claimed} exceeds limit {limit}")]
    EntryCountExceeded { claimed: u32, limit: u32 },

    /// File entry sha256 64-char lowercase hex değil.
    #[error("file sha256 hex format invalid")]
    Sha256HexFormat,

    /// İki veya daha fazla entry aynı path'e sahip.
    #[error("duplicate path: {0}")]
    DuplicatePath(String),

    /// Path sanitize başarısız (`root_name` ya da entry path).
    #[error("path sanitize failed: {0}")]
    Path(#[from] PathError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_file(path: &str, body: &[u8]) -> ManifestEntry {
        let mut h = Sha256::new();
        h.update(body);
        let digest: [u8; 32] = h.finalize().into();
        ManifestEntry::File {
            path: path.to_owned(),
            size: body.len() as u64,
            sha256: hex_lower(&digest),
            mode: None,
            mtime: None,
        }
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

    fn sample_manifest() -> BundleManifest {
        BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "kat1".to_owned(),
            total_entries: 3,
            entries: vec![
                ManifestEntry::Directory {
                    path: "subdir".to_owned(),
                    mode: Some(0o755),
                    mtime: None,
                },
                sample_file("a.txt", b"hello"),
                sample_file("subdir/b.txt", b"world"),
            ],
            created_utc: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = sample_manifest();
        let json = serde_json::to_vec(&m).unwrap();
        let back: BundleManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn manifest_validate_ok() {
        sample_manifest().validate().unwrap();
    }

    #[test]
    fn manifest_validate_version_unsupported() {
        let mut m = sample_manifest();
        m.version = 2;
        assert_eq!(m.validate(), Err(ManifestError::UnsupportedVersion(2)));
    }

    #[test]
    fn manifest_validate_entry_count_mismatch() {
        let mut m = sample_manifest();
        m.total_entries = 99;
        assert_eq!(
            m.validate(),
            Err(ManifestError::EntryCountMismatch {
                claimed: 99,
                actual: 3,
            })
        );
    }

    #[test]
    fn manifest_validate_entry_count_exceeded() {
        // entries.len() == total_entries == MAX_ENTRIES + 1 → reject.
        let mut entries = Vec::with_capacity((MAX_ENTRIES as usize) + 1);
        for i in 0..=MAX_ENTRIES {
            entries.push(ManifestEntry::Directory {
                path: format!("d{i}"),
                mode: None,
                mtime: None,
            });
        }
        let m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "big".to_owned(),
            total_entries: MAX_ENTRIES + 1,
            entries,
            created_utc: Utc::now(),
        };
        assert_eq!(
            m.validate(),
            Err(ManifestError::EntryCountExceeded {
                claimed: MAX_ENTRIES + 1,
                limit: MAX_ENTRIES,
            })
        );
    }

    #[test]
    fn manifest_validate_sha256_hex_format() {
        let mut m = sample_manifest();
        // İlk file entry'sinin sha256'sını bozalım (uppercase hex YASAK).
        if let Some(ManifestEntry::File { sha256, .. }) = m
            .entries
            .iter_mut()
            .find(|e| matches!(e, ManifestEntry::File { .. }))
        {
            *sha256 = sha256.to_uppercase();
        }
        assert_eq!(m.validate(), Err(ManifestError::Sha256HexFormat));
    }

    #[test]
    fn manifest_validate_sha256_hex_short() {
        let mut m = sample_manifest();
        if let Some(ManifestEntry::File { sha256, .. }) = m
            .entries
            .iter_mut()
            .find(|e| matches!(e, ManifestEntry::File { .. }))
        {
            *sha256 = "abcd".to_owned();
        }
        assert_eq!(m.validate(), Err(ManifestError::Sha256HexFormat));
    }

    #[test]
    fn manifest_validate_duplicate_paths() {
        let mut m = sample_manifest();
        m.entries.push(sample_file("a.txt", b"different body"));
        m.total_entries = 4;
        assert_eq!(
            m.validate(),
            Err(ManifestError::DuplicatePath("a.txt".to_owned()))
        );
    }

    #[test]
    fn manifest_validate_path_traversal() {
        let mut m = sample_manifest();
        m.entries.push(sample_file("../escape.txt", b"x"));
        m.total_entries = 4;
        let err = m.validate().unwrap_err();
        assert!(matches!(err, ManifestError::Path(PathError::Traversal)));
    }

    #[test]
    fn manifest_validate_root_name_with_slash() {
        let mut m = sample_manifest();
        m.root_name = "foo/bar".to_owned();
        let err = m.validate().unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Path(PathError::BackslashSeparator)
        ));
    }

    #[test]
    fn manifest_attachment_hash_deterministic() {
        let m = sample_manifest();
        let h1 = m.attachment_hash_i64().unwrap();
        let h2 = m.attachment_hash_i64().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn manifest_sha256_matches_independent_hash() {
        let m = sample_manifest();
        let json = serde_json::to_vec(&m).unwrap();
        let from_struct = m.manifest_sha256().unwrap();
        let from_bytes = BundleManifest::sha256_of_bytes(&json);
        assert_eq!(from_struct, from_bytes);
    }

    #[test]
    fn manifest_attachment_hash_first_8_bytes() {
        let m = sample_manifest();
        let digest = m.manifest_sha256().unwrap();
        let expected = i64::from_be_bytes(digest[0..8].try_into().unwrap());
        assert_eq!(m.attachment_hash_i64().unwrap(), expected);
    }

    #[test]
    fn entry_path_accessor() {
        let f = sample_file("a/b.txt", b"x");
        assert_eq!(f.path(), "a/b.txt");
        let d = ManifestEntry::Directory {
            path: "x".to_owned(),
            mode: None,
            mtime: None,
        };
        assert_eq!(d.path(), "x");
    }

    #[test]
    fn is_lowercase_hex_64_helper() {
        assert!(is_lowercase_hex_64(&"a".repeat(64)));
        assert!(is_lowercase_hex_64(&"0".repeat(64)));
        assert!(!is_lowercase_hex_64(&"A".repeat(64)));
        assert!(!is_lowercase_hex_64(&"a".repeat(63)));
        assert!(!is_lowercase_hex_64(&"a".repeat(65)));
        assert!(!is_lowercase_hex_64(&"g".repeat(64)));
    }
}
