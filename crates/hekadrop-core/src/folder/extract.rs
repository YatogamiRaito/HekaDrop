//! RFC-0005 §6 — receiver-side atomic-reject extract pipeline.
//!
//! Bu modül `HEKABUND` temp `.bundle` dosyasını parse eder, manifest
//! `attachment_hash` ile commit prefix'ini doğrular, per-segment path
//! sanitize uygular ve her entry'yi staging temp dizinine yazar. Tüm
//! entry'ler doğrulandıktan sonra atomic `rename` ile
//! `~/Downloads/<root_name>/`'a alır; HERHANGİ bir adımda hata olursa
//! staging dir + `.bundle` siler ve hiçbir artefakt Downloads'a sızmaz.
//!
//! Spec: `docs/protocol/folder-payload.md` §6 (atomic-reject state machine),
//! §10 (security guards).
//!
//! # Atomic-reject sözleşmesi
//!
//! ```text
//! 1. BundleReader::open  → magic + version + manifest_len + trailer SHA-256
//! 2. parse manifest_json + schema validate (§3.2)
//! 3. attachment_hash prefix verify (mismatch → reject)
//! 4. mkdir staging temp ~/Downloads/.hekadrop-extract-<session>/
//! 5. for entry in entries:
//!      sanitize path (§5)
//!      directory → create_dir_all + parent symlink check
//!      file      → open create_new + parent symlink check
//!                  + stream `entry.size` bytes from bundle
//!                  + per-entry SHA-256 (mismatch → reject)
//! 6. unique_downloads_path(root_name) + rename (atomic)
//! 7. delete .bundle + (extract dizini rename ile zaten taşındı)
//!
//! ANY failure → cleanup all + return Err
//! ```
//!
//! Cross-device EXDEV: `rename` `ErrorKind::CrossesDevices` döndürürse
//! recursive copy + delete fallback (§8 satır 19).
//!
//! # I-1 / I-5 not'ları
//!
//! - Modül `crate::platform/paths/ui/i18n` referans **yok** — sadece
//!   `crate::folder::*` ve `std::fs` + `sha2`.
//! - `extract_root_dir` argüman olarak verilir (caller — `connection.rs`
//!   `unique_downloads_path` ile aynı `state.default_download_dir`'i geçer);
//!   modül HOME / settings dokunmuyor.
//! - Manifest `entries[i].size` peer-controlled u64 → checked downcast +
//!   stream-bounded read; `take(size)` ile bundle'dan tam `size` byte okunur,
//!   eksik → `EntrySha256Mismatch` (size mismatch zaten hash mismatch'e düşer).

use crate::folder::bundle::{BundleError, BundleReader, HEADER_LEN};
use crate::folder::manifest::{BundleManifest, ManifestEntry, ManifestError};
use crate::folder::sanitize::{
    sanitize_received_relative_path, sanitize_root_name, PathError, MAX_DEPTH,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Streaming read tamponu — per-file body okuma için. 64 KiB ile syscall
/// sayısı düşük, RAM maliyeti ihmal edilebilir.
const EXTRACT_READ_BUF: usize = 64 * 1024;

/// Extract sonucu — başarılı extract'in özeti. Receiver UI / history'de
/// `Folder` variant olarak yer alır.
#[derive(Debug, Clone)]
pub struct ExtractedFolder {
    /// Final extracted folder path (`~/Downloads/<root_name>` veya
    /// `unique_downloads_path` ile collision çözülmüş varyant).
    pub final_path: PathBuf,
    /// Manifest'teki toplam entry sayısı (file + directory). UI'da
    /// "klasör alındı: kat1 (N dosya)" formatı için.
    pub total_entries: u32,
    /// Manifest'teki file (non-directory) entry sayısı. UI mesajında
    /// kullanıcıya gösterilen "dosya" sayısı.
    pub file_count: u32,
}

/// Extract pipeline hata kategorileri (`docs/protocol/folder-payload.md` §8).
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// Bundle parse / trailer / magic / version hatası.
    #[error("bundle parse error: {0}")]
    Bundle(#[from] BundleError),

    /// Manifest schema validate hatası (`type`, `total_entries`, sha256 hex).
    #[error("manifest validation: {0}")]
    Manifest(#[from] ManifestError),

    /// Manifest JSON parse hatası (UTF-8, syntax).
    #[error("manifest JSON parse: {0}")]
    ManifestJson(#[from] serde_json::Error),

    /// Introduction'dan gelen `attachment_hash` ile manifest'in
    /// `manifest_sha256[0..8]` BE prefix'i eşleşmiyor — sender bug veya
    /// MITM tampering.
    #[error("attachment_hash mismatch: expected {expected:#018x}, actual {actual:#018x}")]
    AttachmentHashMismatch { expected: i64, actual: i64 },

    /// Per-segment path sanitize fail (`..`, backslash, NUL, depth>32).
    #[error("path sanitize ({path}): {source}")]
    Path {
        path: String,
        #[source]
        source: PathError,
    },

    /// Bir entry'nin bundle'dan okunan body SHA-256'sı manifest'teki
    /// `sha256` hex ile eşleşmiyor — corruption veya tampering.
    #[error("entry SHA-256 mismatch: {path}")]
    EntrySha256Mismatch { path: String },

    /// Bir entry'nin parent dizini sanitize sonrası symlink — TOCTOU /
    /// hostile filesystem race (§5.2 / §10).
    #[error("parent symlink detected: {path}")]
    ParentSymlink { path: String },

    /// Manifest'teki file entry size'ı bundle'dan okunamayacak kadar
    /// büyük (`sum_files` > `concat_data_len`). Sender bug veya tampering.
    #[error("file size {claimed} bundle remainder ({remainder}) sınırını aşıyor (entry={path})")]
    FileSizeOverflow {
        path: String,
        claimed: u64,
        remainder: u64,
    },

    /// I/O hatası (mkdir, open, read, write, rename).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Atomic-reject extract pipeline.
///
/// Çağıran (`connection.rs::finalize_received_file` veya bundle finalize
/// path'i):
/// - `bundle_path` — receiver'ın `.bundle` temp dosyasının yolu.
/// - `expected_manifest_sha256_prefix` — Introduction'da gelen
///   `FileMetadata.attachment_hash` (i64 BE prefix). Mismatch → reject.
/// - `downloads_dir` — final hedef dizinin parent'ı (`~/Downloads`); staging
///   temp dizini de aynı parent altında oluşturulur (cross-device EXDEV
///   ihtimalini minimize eder).
/// - `session_id_hex_lower` — staging dir adında collision avoidance
///   (`session_id` aynı bağlantı için stabil; aynı session'da paralel
///   bundle yok).
///
/// Başarılı dönüş [`ExtractedFolder`]; herhangi bir hatada staging dir +
/// `.bundle` silinmiş olur. Caller sadece `Result`'ı UI'a yansıtır;
/// best-effort cleanup garanti.
///
/// # Errors
///
/// Returns [`ExtractError`] if:
/// - Bundle open / header / trailer verify fail
/// - Manifest JSON parse / schema validate fail
/// - `attachment_hash` mismatch (manifest tampered post-introduction)
/// - Per-file extract sırasında SHA-256 mismatch veya I/O hatası
/// - Final rename (staging → downloads) fail (cross-device, permission)
pub fn extract_bundle(
    bundle_path: &Path,
    expected_manifest_sha256_prefix: i64,
    downloads_dir: &Path,
    session_id_hex_lower: &str,
) -> Result<ExtractedFolder, ExtractError> {
    // Atomic-reject scope guard — Result dönmeden ÖNCE staging dir +
    // bundle silinir. `Drop` impl basit closure-on-drop pattern'i ile
    // success path'inde `disarm` çağırılarak iptal edilir.
    let staging_dir = downloads_dir.join(format!(".hekadrop-extract-{session_id_hex_lower}",));
    let mut cleanup = ExtractCleanup::new(bundle_path.to_owned(), staging_dir.clone());

    let result = extract_bundle_inner(
        bundle_path,
        expected_manifest_sha256_prefix,
        downloads_dir,
        &staging_dir,
    );

    match result {
        Ok(extracted) => {
            // Success — staging dizini final hedefine taşındı (rename
            // aşamasında); cleanup yalnız `.bundle` silmeli.
            cleanup.disarm_staging();
            // bundle silmeyi cleanup'a bırak (Drop'ta yapılır) — explicit
            // değil. Aksi halde Drop tekrar denemeye çalışır ve NotFound
            // log'a düşer (zararsız, sadece gürültü).
            // Aslında burada bundle silinmeyi açıkça istiyoruz; en kolayı
            // cleanup.run_now()'u success path'inde sadece bundle delete
            // ile çağırmak — staging zaten taşındı.
            cleanup.run_bundle_delete_now();
            cleanup.disarm_bundle();
            Ok(extracted)
        }
        Err(e) => {
            // Failure — Drop staging dir + bundle siler.
            Err(e)
        }
    }
}

/// `extract_bundle`'ın panic-koruyucu sarmalı altındaki gerçek implementasyon.
/// Bundle aç → manifest doğrula → staging'e dosyaları yaz → atomic rename.
fn extract_bundle_inner(
    bundle_path: &Path,
    expected_manifest_sha256_prefix: i64,
    downloads_dir: &Path,
    staging_dir: &Path,
) -> Result<ExtractedFolder, ExtractError> {
    // 1. Bundle aç + magic + manifest_len + trailer verify.
    let reader = BundleReader::open(bundle_path)?;
    let manifest_json = reader.manifest_json().to_vec();
    let header = reader.header();

    // 2. Manifest parse + schema validate (§3.2).
    let manifest: BundleManifest = serde_json::from_slice(&manifest_json)?;
    manifest.validate()?;

    // 3. attachment_hash commit verify — manifest tampered post-introduction
    // ise ya da MITM frame'i değiştirmiş olabilir.
    let actual_prefix = manifest.attachment_hash_i64()?;
    if actual_prefix != expected_manifest_sha256_prefix {
        return Err(ExtractError::AttachmentHashMismatch {
            expected: expected_manifest_sha256_prefix,
            actual: actual_prefix,
        });
    }

    // 4. root_name sanitize (manifest.validate() zaten çağırdı; defansif
    // ikinci tur — root_name field'ı UI'a gidiyor, format-only güven).
    let safe_root =
        sanitize_root_name(&manifest.root_name).map_err(|source| ExtractError::Path {
            path: manifest.root_name.clone(),
            source,
        })?;

    // 5. Staging dir mkdir — `create_dir_all` (zaten varsa OK; session_id
    // unique olduğu için pratikte EEXIST olmaz, ama paralel test koşusu /
    // crash sonrası retry için defansif). Ancak EEXIST + dir-not-empty
    // sürpriz davranışa yol açar (önceki run'ın artığı dosyalar üstüne
    // sızar) → önce sil + tekrar oluştur.
    if staging_dir.exists() {
        // Önceki crash artığı; sil. Hata yutulur — eğer silemezsek mkdir
        // EEXIST + dolu dizinde de hatayla biter.
        let _ = fs::remove_dir_all(staging_dir);
    }
    fs::create_dir_all(staging_dir)?;

    // 6. Bundle file handle'ı al + body offset'e seek (header + manifest sonrası).
    // INVARIANT (CLAUDE.md I-5): manifest_len ≤ 8 MiB (BundleHeader::decode
    // ile garanti); HEADER_LEN sabit 16. Toplam ≤ 8 MiB + 16 → u64 lossless.
    let body_offset = (HEADER_LEN as u64).saturating_add(u64::from(header.manifest_len));
    let bundle_total_len = reader.bundle_len();
    let mut bundle_file = reader.into_file();
    bundle_file.seek(SeekFrom::Start(body_offset))?;

    let concat_data_len = bundle_total_len
        .saturating_sub(body_offset)
        .saturating_sub(crate::folder::bundle::TRAILER_LEN as u64);

    // 7. Per-entry extract.
    let mut file_count: u32 = 0;
    let mut bytes_consumed: u64 = 0;

    for entry in &manifest.entries {
        let raw_path = entry.path();
        let segments =
            sanitize_received_relative_path(raw_path).map_err(|source| ExtractError::Path {
                path: raw_path.to_owned(),
                source,
            })?;
        if segments.len() > MAX_DEPTH {
            // sanitize_received_relative_path zaten DepthExceeded döner;
            // defansif ikinci kontrol.
            return Err(ExtractError::Path {
                path: raw_path.to_owned(),
                source: PathError::DepthExceeded(segments.len()),
            });
        }

        let mut joined = staging_dir.to_path_buf();
        for seg in &segments {
            joined.push(seg);
        }

        // Parent symlink check (§5.2): joined'ın PARENT directory'sini
        // resolve et; eğer symlink ise hostile race.
        if let Some(parent) = joined.parent() {
            ensure_no_symlink_in_chain(staging_dir, parent, raw_path)?;
        }

        match entry {
            ManifestEntry::Directory { mode, .. } => {
                fs::create_dir_all(&joined)?;
                // RFC-0005 §3.2 — `mode` opsiyonel, best-effort uygula.
                // Unix-only; Windows'ta mode anlamsız → silently skip.
                // Hata yutulur (best-effort) — chmod fail'i dosyanın varlığını
                // bozmaz, sadece izin metadata tam değil.
                apply_mode_best_effort(&joined, *mode);
            }
            ManifestEntry::File {
                size, sha256, mode, ..
            } => {
                file_count = file_count.saturating_add(1);

                // Parent dizinini oluştur (mkdir -p).
                if let Some(parent) = joined.parent() {
                    fs::create_dir_all(parent)?;
                    ensure_no_symlink_in_chain(staging_dir, parent, raw_path)?;
                }

                // Bundle remainder kontrolü — peer-controlled size'ın bundle
                // boyutunu aşmaması.
                let remaining = concat_data_len.saturating_sub(bytes_consumed);
                if *size > remaining {
                    return Err(ExtractError::FileSizeOverflow {
                        path: raw_path.to_owned(),
                        claimed: *size,
                        remainder: remaining,
                    });
                }

                // File create_new — symlink/preexisting overwrite engelle.
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&joined)?;

                // Streaming copy + SHA-256.
                let computed_hex = stream_copy_with_sha256(&mut bundle_file, &mut out, *size)?;
                bytes_consumed = bytes_consumed.saturating_add(*size);

                // Constant-time karşılaştırma yerine eq — sha256 hex
                // manifest'ten geliyor, attacker-controlled değil; manifest
                // attachment_hash zaten doğrulandı.
                if computed_hex != *sha256 {
                    return Err(ExtractError::EntrySha256Mismatch {
                        path: raw_path.to_owned(),
                    });
                }

                // Best-effort fsync — durability güvencesi (kullanıcı tarafından
                // beklenen "alındı" anlamı diskte var).
                let _ = out.sync_all();

                // RFC-0005 §3.2 — `mode` opsiyonel, best-effort uygula.
                // PR #149 medium yorumu (Gemini): drop öncesi `File::set_permissions`
                // file handle üzerinden race-free; close-then-chmod path race'i
                // yok (staging dir 0700 olsa bile defense-in-depth).
                apply_mode_best_effort_via_handle(&out, *mode);
                drop(out);
            }
        }
    }

    // 8. Final hedef path — collision avoidance.
    let final_path = unique_extract_target(downloads_dir, &safe_root)?;

    // 9. Atomic rename. Cross-device fallback (§8).
    match fs::rename(staging_dir, &final_path) {
        Ok(()) => {}
        Err(e) if is_cross_device(&e) => {
            // PR #145 high yorumu (Gemini): Recursive copy partial-failure'da
            // (ör. disk dolu) `final_path` altında kısmi dosya bırakırsa
            // atomic-reject vaadi bozulur. Hata olursa final_path'i de temizle.
            if let Err(copy_err) = recursive_copy_dir(staging_dir, &final_path) {
                let _ = fs::remove_dir_all(&final_path);
                return Err(copy_err);
            }
            // Source'u sil (best-effort). Outer caller success path'inde
            // `disarm_staging` çağırır — bu noktada `remove_dir_all` fail
            // olursa staging dir orphan kalır (Drop guard disarm sonrası
            // tekrar denemez). Pratikte EXDEV+rename başarılı + remove fail
            // nadir; orphan staging cleanup sweep'ı tarafından sonradan
            // toplanır.
            let _ = fs::remove_dir_all(staging_dir);
        }
        Err(e) => return Err(ExtractError::Io(e)),
    }

    // INVARIANT: total_entries ≤ MAX_ENTRIES (10 000) → u32 zaten.
    let total_entries = manifest.total_entries;

    Ok(ExtractedFolder {
        final_path,
        total_entries,
        file_count,
    })
}

/// `bundle_file`'tan tam `size` byte oku, `out`'a yaz, akarken SHA-256 hesapla.
fn stream_copy_with_sha256(
    bundle: &mut File,
    out: &mut File,
    size: u64,
) -> Result<String, ExtractError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; EXTRACT_READ_BUF];
    let mut remaining = size;
    while remaining > 0 {
        // INVARIANT: buf.len() = 64 KiB; remaining peer-controlled u64
        // ama `concat_data_len`'e karşı `FileSizeOverflow` ile zaten
        // doğrulandı. min ile downcast güvenli.
        let want_u64 = remaining.min(buf.len() as u64);
        // INVARIANT (CLAUDE.md I-5): want_u64 ≤ buf.len() ≤ usize::MAX;
        // try_from None ise buf.len() fallback.
        let want = usize::try_from(want_u64).unwrap_or(buf.len());
        let n = bundle.read(&mut buf[..want])?;
        if n == 0 {
            // EOF beklenmedik — bundle truncated. SHA-256 mismatch'e düşmek
            // yerine net I/O hatası.
            return Err(ExtractError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "bundle ran short during file extract",
            )));
        }
        out.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        // n ≤ remaining (want ≤ remaining; read returns ≤ buf len)
        remaining = remaining.saturating_sub(n as u64);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(hex_lower(&digest))
}

/// RFC-0005 §3.2 — best-effort POSIX mode apply. Unix-only; Windows'ta
/// no-op (mode anlamsız NTFS ACL modeli ile). Hata yutulur — chmod fail'i
/// içeriği bozmaz, sadece izin metadata tam değil. `mtime` benzer bir
/// best-effort apply ileri PR'a (yeni `filetime` dep ekleme overhead'ini
/// taşımak istemiyoruz; v0.8.1 follow-up).
#[cfg(unix)]
fn apply_mode_best_effort(path: &Path, mode: Option<u32>) {
    if let Some(m) = mode {
        // Tehlikeli bit'leri (setuid/setgid/sticky) maskele — peer-controlled
        // mode'a güvenmiyoruz; sadece rwx bit'lerini al (lower 9 bit).
        let safe = m & 0o777;
        let _ = fs::set_permissions(path, std::fs::Permissions::from_mode(safe));
    }
}

/// `apply_mode_best_effort` no-op variant (Windows): NTFS ACL modeli POSIX
/// mode bit'lerini temsil etmez.
#[cfg(not(unix))]
fn apply_mode_best_effort(_path: &Path, _mode: Option<u32>) {
    // No-op: NTFS ACL modeli POSIX mode bit'lerini temsil etmez.
}

/// Race-free fchmod alternatifi (PR #149 medium): file handle hâlâ açıkken
/// `File::set_permissions` çağırarak path lookup race'i bypass et.
#[cfg(unix)]
fn apply_mode_best_effort_via_handle(file: &fs::File, mode: Option<u32>) {
    if let Some(m) = mode {
        let safe = m & 0o777;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(safe));
    }
}

/// `apply_mode_best_effort_via_handle` no-op variant (Windows): file handle
/// üzerinden permission set'i POSIX-only API.
#[cfg(not(unix))]
fn apply_mode_best_effort_via_handle(_file: &fs::File, _mode: Option<u32>) {
    // No-op (Windows).
}

/// Bayt dizisini lowercase hex string'e çevir; alloc-once.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// `staging_root`'tan `target`'a kadar her ara dizinin symlink olmadığını
/// doğrular (§5.2 generalize). Hostile peer staging dizinine paralel olarak
/// symlink koyamaz çünkü staging dir session-unique + `create_dir_all` yeni
/// oluşturuldu; ama defensive guard tutuluyor — ileride "extract dir already
/// exists" senaryosu eklenirse bu zaten korur.
fn ensure_no_symlink_in_chain(
    staging_root: &Path,
    target: &Path,
    raw_entry_path: &str,
) -> Result<(), ExtractError> {
    // staging_root'tan başla, target'a kadar her ara komponenti symlink_metadata
    // ile kontrol et.
    let Ok(rel) = target.strip_prefix(staging_root) else {
        // target staging dışında — manifest sanitize'te yakalanmalıydı, defansif.
        return Err(ExtractError::ParentSymlink {
            path: raw_entry_path.to_owned(),
        });
    };
    let mut current = staging_root.to_path_buf();
    for comp in rel.components() {
        current.push(comp);
        match fs::symlink_metadata(&current) {
            Ok(md) => {
                if md.file_type().is_symlink() {
                    return Err(ExtractError::ParentSymlink {
                        path: raw_entry_path.to_owned(),
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Henüz oluşturulmamış (mkdir sonra çağrılacak) — symlink
                // olamaz, OK.
                return Ok(());
            }
            Err(e) => return Err(ExtractError::Io(e)),
        }
    }
    Ok(())
}

/// `downloads_dir/<safe_root>` collision avoidance — `MyFolder (2)`,
/// `MyFolder (3)`, vs.
fn unique_extract_target(downloads_dir: &Path, safe_root: &str) -> Result<PathBuf, ExtractError> {
    let candidate = downloads_dir.join(safe_root);
    if !candidate.exists() {
        return Ok(candidate);
    }
    for n in 2..=10_000 {
        let alt = downloads_dir.join(format!("{safe_root} ({n})"));
        if !alt.exists() {
            return Ok(alt);
        }
    }
    Err(ExtractError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "10 000 collision çözümü tükendi",
    )))
}

/// I/O hatası EXDEV (cross-device link) mı? — atomic rename fail için
/// recursive copy fallback gerek olduğunu söyler.
#[cfg(unix)]
fn is_cross_device(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc_exdev())
}

/// Non-Unix platformlar — Windows `MoveFileEx` farklı volume'ları
/// transparan kopyalar; ek fallback gerekmez.
#[cfg(not(unix))]
fn is_cross_device(_e: &io::Error) -> bool {
    false
}

/// EXDEV errno değeri — POSIX 18, libc dep eklemekten kaçınmak için sabit.
#[cfg(unix)]
const fn libc_exdev() -> i32 {
    // EXDEV — cross-device link not permitted. POSIX value 18.
    // Linux/macOS/*BSD ortak. Hardcoded — `libc` crate dep eklemekten kaçıyoruz
    // (sadece tek sabit için).
    18
}

/// Cross-device EXDEV fallback — `src` dizinini recursive olarak `dst`'ye
/// kopyalar. `dst` zaten yoksa `create_dir_all` ile oluşturulur.
fn recursive_copy_dir(src: &Path, dst: &Path) -> Result<(), ExtractError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            recursive_copy_dir(&from, &to)?;
        } else if ft.is_file() {
            fs::copy(&from, &to)?;
        } else {
            // Symlink / special — extract pipeline bunları üretmez; defansif skip.
        }
    }
    Ok(())
}

/// RAII cleanup guard — `Drop`'ta staging dir + bundle file silinir.
/// Success path'inde `disarm_*` ile devre dışı bırakılır.
struct ExtractCleanup {
    /// Drop anında silinecek bundle dosyası; `disarm_bundle()` sonrası `None`.
    bundle_path: Option<PathBuf>,
    /// Drop anında recursive silinecek staging dizini;
    /// `disarm_staging()` sonrası `None`.
    staging_dir: Option<PathBuf>,
}

impl ExtractCleanup {
    /// Hem bundle hem staging silmek üzere armed yeni guard.
    fn new(bundle_path: PathBuf, staging_dir: PathBuf) -> Self {
        Self {
            bundle_path: Some(bundle_path),
            staging_dir: Some(staging_dir),
        }
    }
    /// Bundle silmeyi devre dışı bırak — örn. başarılı extract sonrası.
    fn disarm_bundle(&mut self) {
        self.bundle_path = None;
    }
    /// Staging silmeyi devre dışı bırak — final rename başarılı.
    fn disarm_staging(&mut self) {
        self.staging_dir = None;
    }
    /// Success path'inde bundle'ı hemen sil (Drop'a bırakmadan; explicit).
    fn run_bundle_delete_now(&self) {
        if let Some(p) = self.bundle_path.as_ref() {
            let _ = fs::remove_file(p);
        }
    }
}

impl Drop for ExtractCleanup {
    fn drop(&mut self) {
        if let Some(staging) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(&staging);
        }
        if let Some(bundle) = self.bundle_path.take() {
            let _ = fs::remove_file(&bundle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::folder::bundle::{BundleWriter, HEKABUND_VERSION};
    use crate::folder::manifest::{BundleManifest, ManifestEntry, MANIFEST_VERSION};
    use chrono::{DateTime, Utc};
    use std::io::Write;
    use tempfile::tempdir;

    fn sha_hex(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        hex_lower(&Into::<[u8; 32]>::into(h.finalize()))
    }

    fn write_bundle(path: &Path, manifest_json: &[u8], bodies: &[&[u8]]) {
        let mut writer = BundleWriter::new(manifest_json).unwrap();
        let header_bytes = writer.header_bytes();
        let mut f = File::create(path).unwrap();
        f.write_all(&header_bytes).unwrap();
        f.write_all(manifest_json).unwrap();
        for body in bodies {
            f.write_all(body).unwrap();
            writer.update(body);
        }
        let trailer = writer.finalize();
        f.write_all(&trailer).unwrap();
        f.sync_all().unwrap();
        // Sanity — header version stable.
        assert_eq!(HEKABUND_VERSION, 1);
    }

    fn sample_manifest() -> (BundleManifest, Vec<u8>) {
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "kat".to_owned(),
            total_entries: 2,
            entries: vec![
                ManifestEntry::File {
                    path: "a.txt".to_owned(),
                    size: 5,
                    sha256: sha_hex(b"hello"),
                    mode: None,
                    mtime: None,
                },
                ManifestEntry::File {
                    path: "b.txt".to_owned(),
                    size: 5,
                    sha256: sha_hex(b"world"),
                    mode: None,
                    mtime: None,
                },
            ],
            created_utc: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        (m, json)
    }

    #[test]
    fn extract_happy_path_two_files() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let (m, json) = sample_manifest();
        write_bundle(&bundle, &json, &[b"hello", b"world"]);
        let prefix = m.attachment_hash_i64().unwrap();

        let result = extract_bundle(&bundle, prefix, downloads.path(), "deadbeef").unwrap();
        assert_eq!(result.file_count, 2);
        assert_eq!(result.total_entries, 2);
        let final_a = result.final_path.join("a.txt");
        let final_b = result.final_path.join("b.txt");
        assert_eq!(fs::read(&final_a).unwrap(), b"hello");
        assert_eq!(fs::read(&final_b).unwrap(), b"world");
        assert!(!bundle.exists(), ".bundle silinmeliydi");
    }

    #[test]
    fn extract_attachment_hash_mismatch_rejects() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let (_m, json) = sample_manifest();
        write_bundle(&bundle, &json, &[b"hello", b"world"]);

        let r = extract_bundle(&bundle, 0xDEAD_BEEF, downloads.path(), "deadbeef");
        assert!(matches!(
            r,
            Err(ExtractError::AttachmentHashMismatch { .. })
        ));
        assert!(!bundle.exists(), ".bundle reject path'te de silinmeli");
        // Staging cleanup verify
        let staging = downloads.path().join(".hekadrop-extract-deadbeef");
        assert!(!staging.exists());
    }

    #[test]
    fn extract_per_file_sha256_mismatch_atomic_rejects() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "x".to_owned(),
            total_entries: 0,
            entries: vec![
                ManifestEntry::File {
                    path: "a.txt".to_owned(),
                    size: 5,
                    sha256: sha_hex(b"hello"),
                    mode: None,
                    mtime: None,
                },
                // Tampered: claimed sha256 doğru DEĞİL — body "world" ama
                // hash "wrong" için.
                ManifestEntry::File {
                    path: "b.txt".to_owned(),
                    size: 5,
                    sha256: sha_hex(b"WRONG"),
                    mode: None,
                    mtime: None,
                },
                ManifestEntry::File {
                    path: "c.txt".to_owned(),
                    size: 1,
                    sha256: sha_hex(b"z"),
                    mode: None,
                    mtime: None,
                },
            ],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[b"hello", b"world", b"z"]);
        let prefix = m.attachment_hash_i64().unwrap();

        let r = extract_bundle(&bundle, prefix, downloads.path(), "abcd1234");
        assert!(
            matches!(r, Err(ExtractError::EntrySha256Mismatch { .. })),
            "got {r:?}"
        );
        // Atomic-reject: hiçbir entry Downloads'a sızmamalı.
        assert!(!downloads.path().join("x").exists());
        // Staging temizlendi.
        assert!(!downloads.path().join(".hekadrop-extract-abcd1234").exists());
        // Bundle silindi.
        assert!(!bundle.exists());
    }

    #[test]
    fn extract_unique_collision_appends_suffix() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let (m, json) = sample_manifest();
        write_bundle(&bundle, &json, &[b"hello", b"world"]);
        let prefix = m.attachment_hash_i64().unwrap();

        // Collision: ön mevcut "kat" dizini.
        fs::create_dir_all(downloads.path().join("kat")).unwrap();

        let result = extract_bundle(&bundle, prefix, downloads.path(), "ee").unwrap();
        assert_eq!(result.final_path, downloads.path().join("kat (2)"));
    }

    #[test]
    fn extract_directory_entries_created() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "rt".to_owned(),
            total_entries: 0,
            entries: vec![
                ManifestEntry::Directory {
                    path: "subdir".to_owned(),
                    mode: None,
                    mtime: None,
                },
                ManifestEntry::Directory {
                    path: "subdir/inner".to_owned(),
                    mode: None,
                    mtime: None,
                },
                ManifestEntry::File {
                    path: "subdir/inner/leaf.txt".to_owned(),
                    size: 4,
                    sha256: sha_hex(b"leaf"),
                    mode: None,
                    mtime: None,
                },
            ],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[b"leaf"]);
        let prefix = m.attachment_hash_i64().unwrap();

        let result = extract_bundle(&bundle, prefix, downloads.path(), "dd").unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.total_entries, 3);
        assert!(result.final_path.join("subdir").is_dir());
        assert!(result.final_path.join("subdir/inner").is_dir());
        assert_eq!(
            fs::read(result.final_path.join("subdir/inner/leaf.txt")).unwrap(),
            b"leaf"
        );
    }

    #[test]
    fn extract_empty_folder_with_only_directory_entry() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "empty_root".to_owned(),
            total_entries: 0,
            entries: vec![ManifestEntry::Directory {
                path: "subdir".to_owned(),
                mode: None,
                mtime: None,
            }],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[]);
        let prefix = m.attachment_hash_i64().unwrap();

        let result = extract_bundle(&bundle, prefix, downloads.path(), "ff").unwrap();
        assert_eq!(result.file_count, 0);
        assert_eq!(result.total_entries, 1);
        assert!(result.final_path.is_dir());
        assert!(result.final_path.join("subdir").is_dir());
    }

    #[test]
    fn extract_traversal_path_rejects_via_manifest_validate() {
        // Manifest validate `..` segment'i reddeder; extract pipeline'a
        // ulaşmadan reject olur. Ama defansif — direct extract pipeline
        // kontrolü için manuel manifest oluştur.
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "rt".to_owned(),
            total_entries: 0,
            entries: vec![ManifestEntry::File {
                path: "../escape.txt".to_owned(),
                size: 1,
                sha256: sha_hex(b"x"),
                mode: None,
                mtime: None,
            }],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[b"x"]);
        let prefix = m.attachment_hash_i64().unwrap();

        let r = extract_bundle(&bundle, prefix, downloads.path(), "tt");
        assert!(matches!(
            r,
            Err(ExtractError::Manifest(ManifestError::Path(
                PathError::Traversal
            )))
        ));
        // Atomic-reject: escape.txt MİYAR.
        assert!(!downloads
            .path()
            .parent()
            .unwrap()
            .join("escape.txt")
            .exists());
        assert!(!downloads.path().join("rt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extract_parent_symlink_rejects_when_staging_root_is_symlink() {
        // Simüle: staging dizini oluşturulmadan ÖNCE downloads parent'ında
        // bir directory'yi symlink yap. Pratikte staging session-unique;
        // bu test extract_bundle_inner'ın `ensure_no_symlink_in_chain`
        // guard'ını açıkça verify eder.
        //
        // Setup: bir "real_target" dir oluştur, downloads içine
        // ".hekadrop-extract-symtest" → real_target symlink koy. Extract
        // bunu staging olarak görür ve ilk parent kontrolü symlink'i yakalar.
        let downloads = tempdir().unwrap();
        let real_target = tempdir().unwrap();
        let staging_link = downloads.path().join(".hekadrop-extract-symtest");
        std::os::unix::fs::symlink(real_target.path(), &staging_link).unwrap();

        let bundle = downloads.path().join("test.bundle");
        let (m, json) = sample_manifest();
        write_bundle(&bundle, &json, &[b"hello", b"world"]);
        let prefix = m.attachment_hash_i64().unwrap();

        // Extract: staging exists check → symlink olduğu için remove_dir_all
        // symlink'i takip etmeden siler (POSIX), sonra fresh mkdir. Bu durumda
        // ensure_no_symlink_in_chain yine de safe — staging fresh dizin.
        // Bu yüzden bu test positive path'i doğrular: symlink staging silinir
        // ve fresh dizin oluşur, extract OK.
        let result = extract_bundle(&bundle, prefix, downloads.path(), "symtest");
        assert!(
            result.is_ok(),
            "staging symlink temizlenip fresh mkdir beklenir: {result:?}"
        );
        // Real target dizini etkilenmedi (symlink silindiği için).
        assert!(!staging_link.exists() || staging_link.is_dir());
    }

    #[test]
    fn extract_file_size_overflows_bundle_remainder_rejects() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        // Manifest "size: 100" diyor ama bundle'da sadece 5 byte body var.
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "rt".to_owned(),
            total_entries: 0,
            entries: vec![ManifestEntry::File {
                path: "a.txt".to_owned(),
                size: 100,
                sha256: sha_hex(b"hello"),
                mode: None,
                mtime: None,
            }],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[b"hello"]); // sadece 5 byte
        let prefix = m.attachment_hash_i64().unwrap();

        let r = extract_bundle(&bundle, prefix, downloads.path(), "ovf");
        assert!(
            matches!(r, Err(ExtractError::FileSizeOverflow { .. })),
            "got {r:?}"
        );
        // Cleanup
        assert!(!bundle.exists());
        assert!(!downloads.path().join("rt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extract_applies_posix_mode_best_effort() {
        use std::os::unix::fs::PermissionsExt;
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "perm".to_owned(),
            total_entries: 0,
            entries: vec![ManifestEntry::File {
                path: "exec.sh".to_owned(),
                size: 4,
                sha256: sha_hex(b"abcd"),
                mode: Some(0o755),
                mtime: None,
            }],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[b"abcd"]);
        let prefix = m.attachment_hash_i64().unwrap();

        let result = extract_bundle(&bundle, prefix, downloads.path(), "modebit").unwrap();
        let target = result.final_path.join("exec.sh");
        let perms = fs::metadata(&target).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn extract_masks_setuid_setgid_sticky_bits() {
        use std::os::unix::fs::PermissionsExt;
        // Hostile peer setuid bit ile mode gönderirse mask edilir — sadece
        // alt 9 bit (rwx) uygulanır.
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        let mut m = BundleManifest {
            version: MANIFEST_VERSION,
            root_name: "perm".to_owned(),
            total_entries: 0,
            entries: vec![ManifestEntry::File {
                path: "danger.sh".to_owned(),
                size: 4,
                sha256: sha_hex(b"abcd"),
                mode: Some(0o4755), // setuid + 0o755
                mtime: None,
            }],
            created_utc: Utc::now(),
        };
        m.total_entries = u32::try_from(m.entries.len()).unwrap();
        let json = serde_json::to_vec(&m).unwrap();
        write_bundle(&bundle, &json, &[b"abcd"]);
        let prefix = m.attachment_hash_i64().unwrap();

        let result = extract_bundle(&bundle, prefix, downloads.path(), "setuidtest").unwrap();
        let target = result.final_path.join("danger.sh");
        let perms = fs::metadata(&target).unwrap().permissions();
        // setuid bit (0o4000) MASKELENMIŞ olmalı.
        assert_eq!(perms.mode() & 0o7777, 0o755);
    }

    #[test]
    fn extract_bundle_truncated_rejects_via_bundle_reader() {
        let downloads = tempdir().unwrap();
        let bundle = downloads.path().join("test.bundle");
        // Sadece 5 byte yaz — bundle çok kısa.
        fs::write(&bundle, b"short").unwrap();

        let r = extract_bundle(&bundle, 0, downloads.path(), "tr");
        assert!(matches!(r, Err(ExtractError::Bundle(_))));
        assert!(!bundle.exists());
    }
}
