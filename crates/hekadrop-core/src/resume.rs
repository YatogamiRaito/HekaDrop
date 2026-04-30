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

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// RFC-0004 §5: bir `.meta`'nın `updated_at`'inden itibaren geçerli kabul
/// edildiği gün sayısı. Bu süreden eski meta'lar resume yolu açıldığında
/// sessizce silinir + fresh transfer başlar; PR-E'deki [`cleanup_sweep`]
/// startup'ta da bu eşiği uygular. v0.8.0 hardcoded; v0.8.1'de settings'e
/// taşınır.
pub const RESUME_TTL_DAYS: i64 = 7;

/// RFC-0004 §3.6: `~/.hekadrop/partial/` directory'nin toplam disk
/// kullanımı için soft budget. [`cleanup_sweep`] bu sınırı aşan setleri
/// `updated_at` ESKİ-İLK (LRU) sırasıyla siler. v0.8.0 hardcoded 5 GiB;
/// v0.8.1'de settings'e taşınır.
pub const RESUME_BUDGET_BYTES_DEFAULT: u64 = 5 * 1024 * 1024 * 1024;

/// RFC-0004 §1: receiver Introduction sonrası `ResumeHint` emit etmek için
/// 2 sn süresi var. Sender bu süre içinde frame görmezse `start_offset = 0`
/// legacy fresh transfer'a düşer (silent fallback). Spec normative değer;
/// PR-E sabitlerin tek noktasına taşıdı (sender duplicate'i kaldırıldı).
pub const RESUME_HINT_TIMEOUT: Duration = Duration::from_millis(2000);

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
    #[expect(
        clippy::cast_sign_loss,
        reason = "bit-cast for hex rendering, not arithmetic — round-trip via parse_session_hex"
    )]
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
    /// PR-G: receiver-side absolute path of the partial download file. When
    /// non-empty, [`connection`] resume orchestration reuses this exact path
    /// (skipping fresh `unique_downloads_path` placeholder allocation) so the
    /// existing `.part` bytes survive the second handshake.
    ///
    /// Optional (`#[serde(default)]`) — backward-compatible with older `.meta`
    /// files that predate the field; on absence caller falls back to the
    /// fresh placeholder path (resume effectively no-op).
    #[serde(default)]
    pub dest_path: String,
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

    /// Validate-bypass JSON parser — yalnızca cleanup yolunda kullanılır.
    ///
    /// `load` schema/path/total guard'larını çalıştırır; corrupted ya da
    /// future-version `.meta` dosyaları `Err(InvalidData)` döner ve cleanup
    /// onları silebilmeli (yoksa "kötü meta + iyi meta budget hesabı" tutar).
    /// Bu varyant sadece `serde_json` parse eder; gözlemleneni döner.
    ///
    /// Caller convention: I/O error → caller skip (warn + continue);
    /// `Ok(None)` → `NotFound`; parse fail → `Err(InvalidData)`.
    pub fn load_unchecked(path: &Path) -> io::Result<Option<Self>> {
        let file = match File::open(path) {
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
    #[expect(
        clippy::cast_possible_wrap,
        reason = "bit-cast round-trip of session_id_i64's bit pattern (inverse of meta_filename)"
    )]
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
// Cleanup sweep — RFC-0004 §3.6
// ─────────────────────────────────────────────────────────────────────────────

/// `cleanup_sweep` iç inventarisi — yalnızca aday toplama + LRU sıralama
/// için kullanılır; caller görmez.
struct Candidate {
    meta_path: PathBuf,
    part_path: PathBuf,
    part_size: u64,
    updated_at: DateTime<Utc>,
    session_id: i64,
    payload_id: i64,
}

/// [`cleanup_sweep`] istatistik raporu — caller log/metrics için kullanır.
#[derive(Debug, Default, Clone, Copy)]
pub struct CleanupReport {
    /// TTL aşımı nedeniyle silinen `.meta` (ve eşleşen `.part`) çift sayısı.
    pub removed_ttl: usize,
    /// Budget LRU pass'inde silinen çift sayısı.
    pub removed_budget: usize,
    /// `in_use` setinin koruduğu çift sayısı (aktif transferler).
    pub kept_in_use: usize,
    /// Sweep süresince free edilen toplam `.part` byte sayısı.
    pub bytes_freed: u64,
    /// Sweep sonunda directory'de kalan toplam `.part` byte sayısı.
    pub bytes_remaining: u64,
}

/// Cleanup sweep — `~/.hekadrop/partial/` directory'yi maintain eder.
///
/// İki aşama:
///   1. TTL aşan `.meta` (ve eşleşen `.part`) dosyalarını sil.
///   2. Toplam budget'ı aşıyorsa `updated_at` ESKİ-İLK (LRU) sırasıyla sil.
///
/// `in_use` setindeki `(session_id, payload_id)` çiftleri DOKUNULMAZ — aktif
/// transferler korunur. Caller bu set'i `PayloadAssembler`'dan türetir;
/// startup'ta boş `HashSet` geçer (henüz aktif transfer yok).
///
/// I/O hataları sweep'i durdurmaz; her dosya bağımsız işlenir, hata
/// `tracing::warn` ile loglanır. Toplam istatistik döner.
///
/// Corrupted `.meta` dosyaları (parse hatası) da silinir — yoksa süresiz
/// disk kalır + budget hesabını bozar. Eşleşen `.part` mevcut değilse
/// `.meta` tek başına silinir (yetim meta).
pub fn cleanup_sweep(
    dir: &Path,
    ttl_days: i64,
    budget_bytes: u64,
    in_use: &HashSet<(i64, i64)>,
) -> CleanupReport {
    let mut report = CleanupReport::default();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("[resume cleanup] read_dir({}) failed: {e}", dir.display());
            return report;
        }
    };

    // İlk pass: tüm `.meta` dosyalarını topla. Corrupted parse → hemen sil
    // (budget hesabını bozmasın). I/O error → skip + warn.
    let mut candidates: Vec<Candidate> = Vec::new();

    // PR #135 Gemini medium: `flatten()` I/O hatalarını sessizce yutar; hatalı
    // entry'yi `tracing::warn` ile loglayıp skip et — silent data corruption riskini
    // ortadan kaldırır.
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!("[resume cleanup] dizin okuma hatası: {err}");
                continue;
            }
        };
        let meta_path = entry.path();
        // Yalnızca `.meta` ile bitenleri işle; `.tmp`/`.part` skip.
        if meta_path.extension().is_none_or(|ext| ext != "meta") {
            continue;
        }

        let loaded = match PartialMeta::load_unchecked(&meta_path) {
            Ok(Some(m)) => m,
            Ok(None) => continue, // race: silindi
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                // Corrupted `.meta` — sil + eşleşen `.part`'ı (varsa) da sil.
                // `.part` adını dosya adından türetelim: `<base>.part`.
                tracing::warn!(
                    "[resume cleanup] corrupted .meta removed: {} ({e})",
                    meta_path.display()
                );
                let part_path = part_path_for_meta(&meta_path);
                let freed = file_size_or_zero(&part_path);
                remove_pair(&meta_path, &part_path);
                report.removed_ttl = report.removed_ttl.saturating_add(1);
                report.bytes_freed = report.bytes_freed.saturating_add(freed);
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "[resume cleanup] .meta read failed (skip): {} ({e})",
                    meta_path.display()
                );
                continue;
            }
        };

        // `.part` aday ismi: `<sid_hex>_<payload>.part`.
        let Some(session_id) = parse_session_hex(&loaded.session_id_hex) else {
            // session_id_hex format bozuk → corrupted muamelesi.
            tracing::warn!(
                "[resume cleanup] invalid session_id_hex, removing: {}",
                meta_path.display()
            );
            let part_path = part_path_for_meta(&meta_path);
            let freed = file_size_or_zero(&part_path);
            remove_pair(&meta_path, &part_path);
            report.removed_ttl = report.removed_ttl.saturating_add(1);
            report.bytes_freed = report.bytes_freed.saturating_add(freed);
            continue;
        };
        // INVARIANT: bit-cast for filename rendering — matches meta_filename.
        #[expect(
            clippy::cast_sign_loss,
            reason = "bit-cast for hex filename rendering — matches meta_filename"
        )]
        let session_u = session_id as u64;
        let part_path = dir.join(format!("{session_u:016x}_{}.part", loaded.payload_id));
        let part_size = file_size_or_zero(&part_path);

        candidates.push(Candidate {
            meta_path,
            part_path,
            part_size,
            updated_at: loaded.updated_at,
            session_id,
            payload_id: loaded.payload_id,
        });
    }

    // Aşama 1: TTL pass + in_use guard.
    let now = Utc::now();
    let ttl = chrono::Duration::days(ttl_days);
    let mut survivors: Vec<Candidate> = Vec::with_capacity(candidates.len());
    // PR #135 medium (3 yorum birleşik): aktif transferlerin `.part` boyutu
    // budget hesabından dışarı bırakılırsa overshoot oluşur (in_use 4 GiB +
    // survivors 1 GiB, budget 5 GiB → sweep "1 GiB ≤ 5 GiB OK" der ama disk
    // gerçek 5 GiB sınırını zaten aşmış). `in_use_size` ayrı topla, budget
    // karşılaştırmasında ekle; LRU evict yine yalnız survivors üstünde döner
    // (in_use dosyalar dokunulmaz). `bytes_remaining` final disk truth'unu
    // yansıtır (in_use + survivors).
    let mut in_use_size: u64 = 0;

    for cand in candidates {
        if in_use.contains(&(cand.session_id, cand.payload_id)) {
            // Aktif transfer — dokunma + LRU adayı değil; ancak boyutu disk
            // gerçeğine dahil → budget hesabında say.
            in_use_size = in_use_size.saturating_add(cand.part_size);
            report.kept_in_use = report.kept_in_use.saturating_add(1);
            continue;
        }
        let age = now.signed_duration_since(cand.updated_at);
        if age > ttl {
            let freed = cand.part_size;
            remove_pair(&cand.meta_path, &cand.part_path);
            report.removed_ttl = report.removed_ttl.saturating_add(1);
            report.bytes_freed = report.bytes_freed.saturating_add(freed);
            continue;
        }
        survivors.push(cand);
    }

    // Aşama 2: Budget LRU pass — `in_use_size`'ı dahil ederek karşılaştır.
    let survivor_total: u64 = survivors
        .iter()
        .map(|c| c.part_size)
        .fold(0u64, u64::saturating_add);
    let total = survivor_total.saturating_add(in_use_size);

    if total > budget_bytes {
        // Eski-ilk sırala (ascending updated_at) — yalnız survivors evict edilebilir.
        survivors.sort_by_key(|c| c.updated_at);
        let mut current = total;
        let mut idx = 0;
        while current > budget_bytes && idx < survivors.len() {
            let cand = &survivors[idx];
            let freed = cand.part_size;
            remove_pair(&cand.meta_path, &cand.part_path);
            report.removed_budget = report.removed_budget.saturating_add(1);
            report.bytes_freed = report.bytes_freed.saturating_add(freed);
            current = current.saturating_sub(freed);
            idx += 1;
        }
        // INVARIANT: `current` >= `in_use_size` her zaman (yalnız survivors evict
        // edilir). `current > budget_bytes` hâlâ true ise budget overshoot
        // in_use dosyaları yüzünden kaçınılmaz — caller log/metric ile farkında.
        report.bytes_remaining = current;
    } else {
        report.bytes_remaining = total;
    }

    report
}

/// `.meta` path'inden `.part` path'i türet (`stem + ".part"`). Cleanup'ın
/// corrupted-meta yolunda `PartialMeta` parse edilemediği için filesystem
/// adından çıkarmak gerekir.
fn part_path_for_meta(meta_path: &Path) -> PathBuf {
    let stem = meta_path.file_stem().unwrap_or_default();
    let mut part_name = stem.to_os_string();
    part_name.push(".part");
    meta_path.with_file_name(part_name)
}

/// Best-effort dosya boyutu; missing/error → `0` (caller log'lamaz, çünkü
/// `.part` opsiyonel — yetim `.meta` legitimate bir durum).
fn file_size_or_zero(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |m| m.len())
}

/// `.meta` + `.part` çiftini sil. Her birini bağımsız işle; `NotFound` silent.
fn remove_pair(meta_path: &Path, part_path: &Path) {
    if let Err(e) = fs::remove_file(meta_path) {
        if e.kind() != ErrorKind::NotFound {
            tracing::warn!(
                "[resume cleanup] failed to remove {}: {e}",
                meta_path.display()
            );
        }
    }
    if let Err(e) = fs::remove_file(part_path) {
        if e.kind() != ErrorKind::NotFound {
            tracing::warn!(
                "[resume cleanup] failed to remove {}: {e}",
                part_path.display()
            );
        }
    }
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
            dest_path: String::new(),
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

    // ─────────────────────────────────────────────────────────────────────
    // PR-E: cleanup_sweep tests
    // ─────────────────────────────────────────────────────────────────────

    /// `.meta` + opsiyonel `.part` çifti yarat. `part_size` byte'lık dummy
    /// `.part` yazar; `None` → `.part` oluşturulmaz (yetim meta testi için).
    fn write_pair(
        dir: &Path,
        session_id: i64,
        payload_id: i64,
        updated_at: DateTime<Utc>,
        part_size: Option<usize>,
    ) {
        let meta_name = meta_filename(session_id, payload_id);
        #[expect(clippy::cast_sign_loss, reason = "test: bit-cast for hex render")]
        let session_u = session_id as u64;
        let bytes = part_size.unwrap_or(0);
        // INVARIANT: test uses small sizes (≤ MiB); i64::try_from cannot fail.
        let bytes_i64 = i64::try_from(bytes).expect("test fixture size fits in i64");
        let meta = PartialMeta {
            version: 1,
            session_id_hex: format!("{session_u:016x}"),
            payload_id,
            file_name: format!("test_{payload_id}.bin"),
            total_size: bytes_i64,
            received_bytes: bytes_i64,
            chunk_size: CHUNK_SIZE,
            chunk_hmac_chain_b64: "AAAA".to_string(),
            peer_endpoint_id: "PEER".to_string(),
            created_at: updated_at,
            updated_at,
            dest_path: String::new(),
        };
        // store_atomic validate eder; total/received eşit + valid → OK.
        meta.store_atomic(dir).unwrap();
        // store_atomic atomic rename kullanır → final path mevcut.
        let _ = meta_name;

        if let Some(size) = part_size {
            let part_name = format!("{session_u:016x}_{payload_id}.part");
            let part_path = dir.join(&part_name);
            let mut f = File::create(&part_path).unwrap();
            f.write_all(&vec![0u8; size]).unwrap();
            f.sync_all().unwrap();
        }
    }

    #[test]
    fn cleanup_skips_in_use() {
        let dir = unique_tmp_dir("cleanup-in-use");
        let now = Utc::now();
        // 3 çift; ikisi in_use (TTL aşmasa da budget olmasa da in_use guard).
        write_pair(&dir, 1, 100, now, Some(1024));
        write_pair(&dir, 2, 200, now, Some(1024));
        // Üçüncü TTL aşan — silinmeli.
        write_pair(&dir, 3, 300, now - chrono::Duration::days(30), Some(1024));

        let mut in_use = HashSet::new();
        in_use.insert((1i64, 100i64));
        in_use.insert((2i64, 200i64));

        let report = cleanup_sweep(&dir, RESUME_TTL_DAYS, RESUME_BUDGET_BYTES_DEFAULT, &in_use);

        assert_eq!(report.kept_in_use, 2, "in_use çiftleri korunmalı");
        assert_eq!(report.removed_ttl, 1, "TTL aşan tek çift silinmeli");
        // PR #135 medium: in_use boyutu `bytes_remaining`'e dahil — disk
        // gerçeği = 2 × 1024 (in_use) + 0 survivor = 2048.
        assert_eq!(report.bytes_remaining, 2048);
        // in_use çiftleri hâlâ yerinde olmalı (.meta + .part).
        assert!(dir.join(meta_filename(1, 100)).exists());
        assert!(dir.join(meta_filename(2, 200)).exists());
        assert!(!dir.join(meta_filename(3, 300)).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_in_use_counts_toward_budget() {
        // PR #135 medium (3 yorum birleşik): aktif transferin `.part` boyutu
        // budget hesabına girmeli — yoksa in_use 4 GiB + survivors 1 GiB +
        // budget 5 GiB durumunda sweep "OK" der ama disk gerçek 5 GiB +
        // sonraki write → 5 GiB sınırı aşılır.
        //
        // Test scale: in_use 3 MiB + 2 survivor × 2 MiB = 7 MiB total.
        // Budget 5 MiB → in_use dahil edildiği için survivors üstünden 2 MiB
        // (en eski) evict edilmeli. Edilmezse (eski davranış) 4 MiB ≤ 5 MiB
        // OK görünür ve LRU tetiklenmez.
        let dir = unique_tmp_dir("cleanup-in-use-budget");
        let now = Utc::now();
        let three_mib = 3 * 1024 * 1024;
        let two_mib = 2 * 1024 * 1024;

        // in_use: 3 MiB.
        write_pair(&dir, 1, 100, now, Some(three_mib));
        // Survivors: 2 MiB her biri, ikincisi yeni.
        write_pair(
            &dir,
            2,
            200,
            now - chrono::Duration::hours(2),
            Some(two_mib),
        ); // en eski
        write_pair(
            &dir,
            3,
            300,
            now - chrono::Duration::hours(1),
            Some(two_mib),
        );

        let mut in_use = HashSet::new();
        in_use.insert((1i64, 100i64));

        let budget: u64 = 5 * 1024 * 1024;
        let report = cleanup_sweep(&dir, RESUME_TTL_DAYS, budget, &in_use);

        assert_eq!(report.kept_in_use, 1);
        assert_eq!(report.removed_ttl, 0);
        assert_eq!(
            report.removed_budget, 1,
            "in_use boyutu (3 MiB) dahil edildiği için en eski survivor evict edilmeli"
        );
        assert_eq!(report.bytes_freed as usize, two_mib);
        // En eski survivor (2,200) evict; (1,100) in_use korundu; (3,300) survivor.
        assert!(dir.join(meta_filename(1, 100)).exists(), "in_use korunmalı");
        assert!(
            !dir.join(meta_filename(2, 200)).exists(),
            "en eski survivor evict"
        );
        assert!(dir.join(meta_filename(3, 300)).exists());
        // bytes_remaining = in_use (3 MiB) + survivor (2 MiB) = 5 MiB.
        assert_eq!(report.bytes_remaining as usize, 5 * 1024 * 1024);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_ttl_expiry_removes() {
        let dir = unique_tmp_dir("cleanup-ttl");
        let now = Utc::now();
        // Eski (10 gün) → silinmeli; yeni (1 gün) → kalmalı.
        write_pair(&dir, 1, 10, now - chrono::Duration::days(10), Some(2048));
        write_pair(&dir, 2, 20, now - chrono::Duration::days(1), Some(2048));

        let report = cleanup_sweep(
            &dir,
            RESUME_TTL_DAYS,
            RESUME_BUDGET_BYTES_DEFAULT,
            &HashSet::new(),
        );

        assert_eq!(report.removed_ttl, 1);
        assert_eq!(report.removed_budget, 0);
        assert_eq!(report.bytes_freed, 2048);
        assert!(!dir.join(meta_filename(1, 10)).exists());
        assert!(dir.join(meta_filename(2, 20)).exists());
        assert_eq!(report.bytes_remaining, 2048);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_lru_eviction_to_budget() {
        let dir = unique_tmp_dir("cleanup-lru");
        let now = Utc::now();
        // 3 dosya × 2 MiB = 6 MiB total, budget = 5 MiB → en eski silinmeli.
        // (Test scale küçük: gerçek 5 GiB yerine 5 MiB; aynı LRU mantığı.)
        let two_mib = 2 * 1024 * 1024;
        write_pair(&dir, 1, 1, now - chrono::Duration::hours(3), Some(two_mib)); // en eski
        write_pair(&dir, 2, 2, now - chrono::Duration::hours(2), Some(two_mib));
        write_pair(&dir, 3, 3, now - chrono::Duration::hours(1), Some(two_mib));

        let budget: u64 = 5 * 1024 * 1024;
        let report = cleanup_sweep(&dir, RESUME_TTL_DAYS, budget, &HashSet::new());

        assert_eq!(report.removed_ttl, 0);
        assert_eq!(report.removed_budget, 1, "yalnız en eski silinmeli");
        assert_eq!(report.bytes_freed as usize, two_mib);
        // En eski (1, 1) silindi; (2,2) ve (3,3) kaldı.
        assert!(!dir.join(meta_filename(1, 1)).exists());
        assert!(dir.join(meta_filename(2, 2)).exists());
        assert!(dir.join(meta_filename(3, 3)).exists());
        assert_eq!(report.bytes_remaining as usize, 4 * 1024 * 1024);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_corrupted_meta_removed() {
        let dir = unique_tmp_dir("cleanup-corrupt");
        // Bozuk JSON yaz — `load_unchecked` parse fail → cleanup silmeli.
        let bad_meta = dir.join("0000000000000099_5.meta");
        let mut f = File::create(&bad_meta).unwrap();
        f.write_all(b"{ this is not valid json").unwrap();
        f.sync_all().unwrap();
        drop(f);
        // Eşleşen `.part` de yarat (corrupted yolun part'ı da silmesini doğrula).
        let bad_part = dir.join("0000000000000099_5.part");
        let mut p = File::create(&bad_part).unwrap();
        p.write_all(&[0u8; 512]).unwrap();
        p.sync_all().unwrap();
        drop(p);

        let report = cleanup_sweep(
            &dir,
            RESUME_TTL_DAYS,
            RESUME_BUDGET_BYTES_DEFAULT,
            &HashSet::new(),
        );

        // Corrupted bucket'a removed_ttl olarak sayılır (caller perspektifinden
        // "expired/invalid" aynı anlam taşır — single counter yeterli).
        assert!(report.removed_ttl >= 1, "corrupted .meta silinmeli");
        assert!(!bad_meta.exists());
        assert!(!bad_part.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_hex_parse_roundtrip() {
        for &id in &[0i64, 1, -1, i64::MIN, i64::MAX, 0x0123_4567_89AB_CDEF] {
            #[expect(clippy::cast_sign_loss, reason = "test: bit-cast for hex render")]
            let hex = format!("{:016x}", id as u64);
            let parsed = parse_session_hex(&hex).unwrap();
            assert_eq!(parsed, id);
        }
    }
}
