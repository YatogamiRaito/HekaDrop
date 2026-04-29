//! RFC-0004 — Transfer resume primitives.
//!
//! Stateless helpers shared between receiver (writes `.meta` after every
//! verified chunk) and sender (consumes `ResumeHint`, re-hashes local
//! `[0..offset]`, decides resume vs restart). All state lives in the
//! caller; this module owns no mutexes, statics, or singletons.
//!
//! Surface (RFC-0004 §3.4 + `docs/protocol/resume.md` §3 + §8 birebir):
//!
//! - [`session_id_i64`] — UKEY2 `auth_key` → 64-bit session identifier
//!   (`SHA-256(auth_key)[0..8]` as big-endian `i64`). RFC §3.4.
//! - [`partial_hash_streaming`] — SHA-256 over a `.part` file's first
//!   `offset` bytes, streamed in 1 MiB chunks (no full-file mmap).
//! - [`partial_dir`] — `~/.hekadrop/partial/` ensure (mode `0700` on POSIX).
//! - [`meta_filename`] — `<sid_hex>_<payload>.meta`, deterministic.
//! - [`PartialMeta`] — `.meta` sidecar JSON schema (`load` / `store_atomic`
//!   + `validate` guards: schema version, hex format, path traversal,
//!     `received <= total`, `chunk_size == CHUNK_SIZE`).
//!
//! No behavior change in this PR — receiver/sender wiring lands in PR-C/D.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Wire/disk-level chunk size invariant. Must match `sender.rs::CHUNK_SIZE`
/// (private). Resume `.meta` records this so a receiver written by a future
/// build with a different chunk size cannot be silently consumed.
///
/// Kept in sync manually; if `sender.rs::CHUNK_SIZE` ever changes, bump this
/// and the `validate()` `ChunkSizeMismatch` check will reject older `.meta`
/// files (forward-compat: caller skips → restart from offset 0).
pub const CHUNK_SIZE: u32 = 512 * 1024;

/// Streaming hash buffer (1 MiB). Independent of `CHUNK_SIZE` — purely
/// an I/O batch size, not a protocol invariant.
const HASH_BUF_SIZE: usize = 1024 * 1024;

/// Current `.meta` schema version. Bump on incompatible changes; older
/// readers reject `version > MAX_META_VERSION` and silently restart.
pub const MAX_META_VERSION: u32 = 1;

/// Compute the 64-bit session identifier from the UKEY2 `auth_key`.
///
/// `i64::from_be_bytes(SHA-256(auth_key)[0..8])` — RFC-0004 §3.4 birebir.
/// Both peers compute this independently; receiver echoes it inside
/// `ResumeHint`, sender drops the frame on mismatch
/// (`ResumeReject{SESSION_MISMATCH}`).
#[must_use]
pub fn session_id_i64(auth_key: &[u8]) -> i64 {
    let digest = Sha256::digest(auth_key);
    // INVARIANT: SHA-256 output is always exactly 32 bytes; slicing [0..8]
    // and try_into() into [u8; 8] cannot fail. Constant indices, no
    // peer-controlled input — fold the impossible Err into a zero array
    // (unreachable) so we don't need expect/unwrap.
    let head: [u8; 8] = digest[0..8].try_into().unwrap_or([0u8; 8]);
    i64::from_be_bytes(head)
}

/// Stream SHA-256 over `path[0..offset]` in 1 MiB chunks.
///
/// Errors:
/// - `InvalidInput` if the file is shorter than `offset` (caller must not
///   request a hash of bytes that do not exist on disk; partial truncation
///   detection is the caller's responsibility).
/// - I/O errors from `File::open` / `BufReader::read` propagate as-is.
///
/// Memory: O(1) — fixed [`HASH_BUF_SIZE`] buffer. Does not mmap.
pub fn partial_hash_streaming(path: &Path, offset: u64) -> io::Result<[u8; 32]> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() < offset {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "file shorter than requested offset ({} < {})",
                metadata.len(),
                offset
            ),
        ));
    }

    let mut reader = BufReader::with_capacity(HASH_BUF_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];
    let mut remaining = offset;

    while remaining > 0 {
        // INVARIANT: HASH_BUF_SIZE = 1 MiB ≪ usize::MAX on every supported
        // target; `min` of u64 with usize-as-u64 cannot wrap.
        let take = remaining.min(HASH_BUF_SIZE as u64);
        // SAFETY-CAST: `take <= HASH_BUF_SIZE` (line above) → fits usize.
        #[allow(clippy::cast_possible_truncation)] // INVARIANT: bounded by HASH_BUF_SIZE
        let take_usize = take as usize;
        reader.read_exact(&mut buf[..take_usize])?;
        hasher.update(&buf[..take_usize]);
        remaining -= take;
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Resolve `~/.hekadrop/partial/`, creating intermediate directories
/// idempotently. POSIX: chmod `0700` after creation; Windows: ACL inherited
/// from parent (no explicit hardening here — hekadrop-app sets DACL on the
/// app data root at install).
///
/// I-1 compliance: uses `std::env::var("HOME")` / `USERPROFILE` directly
/// rather than `crate::paths::*` (app-only) or `dirs` (extra dep).
pub fn partial_dir() -> io::Result<PathBuf> {
    let home = home_dir().ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            "could not resolve home directory (HOME / USERPROFILE unset)",
        )
    })?;
    let dir = home.join(".hekadrop").join("partial");
    fs::create_dir_all(&dir)?;
    set_dir_mode_0700(&dir)?;
    Ok(dir)
}

#[cfg(unix)]
fn set_dir_mode_0700(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(dir, perms)
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // API: cross-platform Result signature parity
fn set_dir_mode_0700(_dir: &Path) -> io::Result<()> {
    // Windows: DACL hygiene is hekadrop-app's responsibility on the app
    // data root; no per-subdir hardening here.
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    // POSIX: $HOME; Windows: %USERPROFILE%. Empty string treated as unset.
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Deterministic `.meta` filename for a `(session_id, payload_id)` pair.
///
/// Format: `"<16-hex-lowercase>_<payload_decimal>.meta"`. The `session_id`
/// is rendered as `u64` (sign-preserving bit-cast) so two's-complement
/// negative ids do not collide and stay 16 chars wide.
#[must_use]
pub fn meta_filename(session_id: i64, payload_id: i64) -> String {
    // INVARIANT: `as u64` reinterprets the bit pattern only — no value
    // change beyond signedness. 16 hex chars is exact for u64.
    #[allow(clippy::cast_sign_loss)] // INVARIANT: bit-cast for hex rendering, not arithmetic
    let sid_u = session_id as u64;
    format!("{sid_u:016x}_{payload_id}.meta")
}

/// `.meta` sidecar — receiver-local persisted resume state. Schema mirrors
/// `docs/protocol/resume.md` §8 (with the `chunk_size` extension proposed
/// in RFC-0004 AS-3 to detect cross-build chunk size drift).
///
/// **Not on wire.** Loaded at Introduction handler entry; persisted after
/// every verified chunk via [`store_atomic`](Self::store_atomic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartialMeta {
    /// Schema version. `validate()` rejects `> MAX_META_VERSION`.
    pub version: u32,
    /// Session identifier as 16-char lowercase hex (`format!("{:016x}", id as u64)`).
    /// Stored as hex (not int64) for human-readable filenames + grep affinity.
    pub session_id_hex: String,
    pub payload_id: i64,
    /// Sanitized file name from `Introduction.FileMetadata`. `validate()`
    /// rejects path separators / null bytes / `..` traversal attempts.
    pub file_name: String,
    pub total_size: i64,
    /// Chunk-aligned. `validate()` rejects `> total_size`.
    pub received_bytes: i64,
    /// Chunk size at the time `.meta` was written. Resume rejected if it
    /// disagrees with the current build's `CHUNK_SIZE` (RFC-0004 AS-3).
    pub chunk_size: u32,
    /// Last verified chunk's HMAC tag (base64). Allows O(1) sender-side
    /// verification when `CHUNK_HMAC_V1` capability is negotiated.
    pub chunk_hmac_chain_b64: String,
    /// mDNS endpoint id of the peer that owns this `.part`. Used to filter
    /// resume eligibility to the originating sender.
    pub peer_endpoint_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("schema version {actual} unsupported (expected ≤ {max})")]
    UnsupportedVersion { actual: u32, max: u32 },
    #[error("session_id_hex format invalid (expected 16 lowercase hex chars)")]
    SessionIdFormat,
    #[error("file_name contains path separator, parent traversal, or null byte")]
    FileNamePathTraversal,
    #[error("received_bytes {received} exceeds total_size {total}")]
    ReceivedExceedsTotal { received: i64, total: i64 },
    #[error("received_bytes {0} is negative")]
    ReceivedNegative(i64),
    #[error("total_size {0} is negative")]
    TotalNegative(i64),
    #[error("chunk_size {actual} mismatches CHUNK_SIZE invariant ({expected})")]
    ChunkSizeMismatch { actual: u32, expected: u32 },
}

impl PartialMeta {
    /// Load and validate the `.meta` for `(session_id, payload_id)` from
    /// `dir`. Returns:
    /// - `Ok(Some(meta))` on present + valid
    /// - `Ok(None)` on `NotFound`
    /// - `Err(io::Error)` on JSON parse failure (kind=`InvalidData`),
    ///   validation failure (kind=`InvalidData`), or other I/O.
    ///
    /// Caller convention: any `Err` → silent skip + restart from offset 0
    /// (do not surface to user; resume is best-effort).
    pub fn load(dir: &Path, session_id: i64, payload_id: i64) -> io::Result<Option<Self>> {
        let path = dir.join(meta_filename(session_id, payload_id));
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let reader = BufReader::new(file);
        let meta: Self = serde_json::from_reader(reader).map_err(|e| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!(".meta JSON parse failed: {e}"),
            )
        })?;
        meta.validate()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
        Ok(Some(meta))
    }

    /// Atomically write `self` to `dir` as `<filename>.tmp` then rename.
    ///
    /// POSIX: `fs::rename` is atomic within a filesystem. Windows: `fs::rename`
    /// fails if the target exists, so we explicitly remove first — narrow
    /// race window vs `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` accepted for
    /// receiver-local resume state (sender does not race the receiver here).
    pub fn store_atomic(&self, dir: &Path) -> io::Result<()> {
        self.validate()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;

        let session_id = parse_session_hex(&self.session_id_hex)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "session_id_hex invalid"))?;
        let final_name = meta_filename(session_id, self.payload_id);
        let final_path = dir.join(&final_name);
        let tmp_path = dir.join(format!("{final_name}.tmp"));

        // Truncate-create tmp; serialize pretty for human inspection.
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::other(format!(".meta JSON serialize failed: {e}")))?;
        tmp.write_all(&json)?;
        tmp.sync_all()?;
        drop(tmp);

        #[cfg(windows)]
        {
            // Windows fs::rename rejects existing target; remove first.
            // Best-effort: ignore NotFound, surface other errors.
            match fs::remove_file(&final_path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        fs::rename(&tmp_path, &final_path)
    }

    /// Run all sanity / security guards. Called by `load` and `store_atomic`.
    fn validate(&self) -> Result<(), MetaError> {
        if self.version > MAX_META_VERSION {
            return Err(MetaError::UnsupportedVersion {
                actual: self.version,
                max: MAX_META_VERSION,
            });
        }
        if !is_valid_session_hex(&self.session_id_hex) {
            return Err(MetaError::SessionIdFormat);
        }
        if contains_path_traversal(&self.file_name) {
            return Err(MetaError::FileNamePathTraversal);
        }
        if self.total_size < 0 {
            return Err(MetaError::TotalNegative(self.total_size));
        }
        if self.received_bytes < 0 {
            return Err(MetaError::ReceivedNegative(self.received_bytes));
        }
        if self.received_bytes > self.total_size {
            return Err(MetaError::ReceivedExceedsTotal {
                received: self.received_bytes,
                total: self.total_size,
            });
        }
        if self.chunk_size != CHUNK_SIZE {
            return Err(MetaError::ChunkSizeMismatch {
                actual: self.chunk_size,
                expected: CHUNK_SIZE,
            });
        }
        Ok(())
    }
}

/// `^[0-9a-f]{16}$` — manual char-by-char to avoid pulling `regex`.
fn is_valid_session_hex(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse a 16-char lowercase hex string back into the original `i64`
/// (bit-cast through `u64`).
fn parse_session_hex(s: &str) -> Option<i64> {
    if !is_valid_session_hex(s) {
        return None;
    }
    let raw = u64::from_str_radix(s, 16).ok()?;
    // INVARIANT: bit-cast inverse of `meta_filename`'s `as u64`.
    #[allow(clippy::cast_possible_wrap)] // INVARIANT: round-trip of session_id_i64's bit pattern
    Some(raw as i64)
}

/// Reject any name containing path separators, parent-traversal sequences,
/// or NUL bytes. Conservative — sender's Introduction sanitization is the
/// primary defence; this is defence-in-depth on disk read path.
fn contains_path_traversal(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return true;
    }
    // Reject the exact `..` and `.` directory components, plus any embedded
    // `..` segment between separators (already caught above) or as a prefix.
    if name == "." || name == ".." {
        return true;
    }
    // Reject "..foo" / "foo.." style literal `..` substrings — strict to
    // avoid filesystem-specific normalization surprises.
    if name.contains("..") {
        return true;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_tmp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("hekadrop-resume-{label}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_meta() -> PartialMeta {
        let now = Utc::now();
        PartialMeta {
            version: 1,
            session_id_hex: "0123456789abcdef".to_string(),
            payload_id: 42,
            file_name: "report.pdf".to_string(),
            total_size: 1_000_000,
            received_bytes: 524_288,
            chunk_size: CHUNK_SIZE,
            chunk_hmac_chain_b64: "AAECAwQFBgc=".to_string(),
            peer_endpoint_id: "ABCD".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn session_id_i64_deterministic() {
        let key = b"the quick brown fox jumps over the lazy dog";
        let a = session_id_i64(key);
        let b = session_id_i64(key);
        assert_eq!(a, b);
    }

    #[test]
    fn session_id_i64_different_keys_different_ids() {
        let a = session_id_i64(b"alpha");
        let b = session_id_i64(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn partial_hash_streaming_matches_one_shot() {
        // Deterministic 10 KB buffer (no rand dep needed for the property).
        let data: Vec<u8> = (0..10_000).map(|i| (i * 31 + 7) as u8).collect();
        let dir = unique_tmp_dir("hash-roundtrip");
        let path = dir.join("blob.bin");
        let mut f = File::create(&path).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let streamed = partial_hash_streaming(&path, data.len() as u64).unwrap();
        let mut h = Sha256::new();
        h.update(&data);
        let one_shot: [u8; 32] = h.finalize().into();
        assert_eq!(streamed, one_shot);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_hash_streaming_short_file_errors() {
        let dir = unique_tmp_dir("hash-short");
        let path = dir.join("short.bin");
        let mut f = File::create(&path).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        drop(f);

        let err = partial_hash_streaming(&path, 200).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_atomic_write_roundtrip() {
        let dir = unique_tmp_dir("meta-roundtrip");
        let meta = sample_meta();
        meta.store_atomic(&dir).unwrap();

        let session_id = parse_session_hex(&meta.session_id_hex).unwrap();
        let loaded = PartialMeta::load(&dir, session_id, meta.payload_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, meta);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_load_returns_none_when_missing() {
        let dir = unique_tmp_dir("meta-missing");
        let result = PartialMeta::load(&dir, 0xDEAD_BEEF_CAFE_BABE_u64.cast_signed(), 1).unwrap();
        assert!(result.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_validate_rejects_path_traversal() {
        let mut m = sample_meta();
        m.file_name = "../etc/passwd".to_string();
        match m.validate() {
            Err(MetaError::FileNamePathTraversal) => {}
            other => panic!("expected FileNamePathTraversal, got {other:?}"),
        }

        // Also direct separators / null
        for bad in ["a/b", "a\\b", "a\0b", "..", ".", "", "..foo", "foo.."] {
            let mut m2 = sample_meta();
            m2.file_name = bad.to_string();
            assert!(
                matches!(m2.validate(), Err(MetaError::FileNamePathTraversal)),
                "expected traversal reject for {bad:?}"
            );
        }
    }

    #[test]
    fn meta_validate_rejects_unsupported_version() {
        let mut m = sample_meta();
        m.version = 99;
        match m.validate() {
            Err(MetaError::UnsupportedVersion { actual: 99, max: 1 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn meta_filename_format_lowercase_hex() {
        // session_id = 0x123, payload_id = 7 → 16-char zero-padded hex + "_7.meta"
        let name = meta_filename(0x123, 7);
        assert_eq!(name, "0000000000000123_7.meta");

        // Negative session_id → bit-cast to u64 (Two's-complement)
        let neg = meta_filename(-1, 0);
        assert_eq!(neg, "ffffffffffffffff_0.meta");
    }

    #[test]
    fn meta_validate_rejects_received_exceeds_total() {
        let mut m = sample_meta();
        m.received_bytes = m.total_size + 1;
        assert!(matches!(
            m.validate(),
            Err(MetaError::ReceivedExceedsTotal { .. })
        ));
    }

    #[test]
    fn meta_validate_rejects_chunk_size_mismatch() {
        let mut m = sample_meta();
        m.chunk_size = CHUNK_SIZE + 1;
        assert!(matches!(
            m.validate(),
            Err(MetaError::ChunkSizeMismatch { .. })
        ));
    }

    #[test]
    fn session_hex_parse_roundtrip() {
        for &id in &[0i64, 1, -1, i64::MIN, i64::MAX, 0x0123_4567_89AB_CDEF] {
            #[allow(clippy::cast_sign_loss)] // test: bit-cast for hex render
            let hex = format!("{:016x}", id as u64);
            let parsed = parse_session_hex(&hex).unwrap();
            assert_eq!(parsed, id);
        }
    }
}
