// Test/bench dosyası — production lint'leri test idiomatik kullanımı bozmasın.
// Cast/clone family de gevşek: test verisi hardcoded, numerik safety burada
// odak değil; behavior validation odaklıyız.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::expect_fun_call,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::ignored_unit_patterns,
    clippy::use_self,
    clippy::trivially_copy_pass_by_ref,
    clippy::single_match_else,
    clippy::map_err_ignore,
    clippy::doc_markdown
)]

//! RFC-0005 PR-C — sender folder enumerate + `HEKABUND` bundle stream
//! invariant'ları.
//!
//! Bu test dosyası `hekadrop::folder` (re-export) public API'si üzerinden
//! sender-side folder primitive'lerinin spec uyumunu sabitler:
//!
//! - **Enumerate kontratı:** symlink + special file skip, depth ≤ 32, entry
//!   count ≤ 10 000, root_must_be_directory.
//! - **Manifest build:** per-file streaming SHA-256 doğru, manifest validate
//!   geçer, `attachment_hash_i64` `manifest_sha256[0..8]` BE i64'e eşit
//!   (Introduction frame contract `docs/protocol/folder-payload.md` §4.1).
//! - **Bundle stream:** `BundleWriter` + manifest + per-file body birleşimi
//!   `BundleReader::open` ile parse + trailer verify + `manifest_json`
//!   round-trip. Bu test sender'ın gerçek pipeline'ında ne emit edeceğinin
//!   byte-exact simülasyonudur (in-memory; network yerine `Vec<u8>`).
//! - **Flatten fallback semantiği:** directory entries `concat_data`'ya
//!   katkı vermez, file count fallback'te beklenen file-kind entry sayısı
//!   ile eşleşir.
//!
//! `send_folder_bundle` private async fn — network mock tokio TcpListener
//! E2E PR-D (receiver) merge'inden sonra `crates/hekadrop-app/tests/
//! folder_e2e.rs` harness'ine eklenecek (loopback sender↔receiver).

use hekadrop::folder::{
    build_manifest, bundle_total_size, enumerate_folder, BundleManifest, BundleReader,
    BundleWriter, EntryKind, EnumerateError, ManifestEntry, HEADER_LEN, MAX_FOLDER_ENTRIES,
    TRAILER_LEN,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::{tempdir, NamedTempFile};

fn write_file(dir: &Path, rel: &str, body: &[u8]) {
    let full = dir.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(&full).unwrap();
    f.write_all(body).unwrap();
}

/// PR-C invariant 1 — enumerate, symlink + (Unix) special file skip eder
/// ve görünür file/directory entries döner. Symlink deneyimi sadece Unix
/// hedeflerinde anlamlı; Windows'ta `std::os::windows::fs::symlink_*`
/// admin yetkisi ister, CI'da pratik değil.
#[cfg(unix)]
#[test]
fn enumerate_folder_3_files_skips_symlinks() {
    let tmp = tempdir().unwrap();
    write_file(tmp.path(), "a.txt", b"alpha");
    write_file(tmp.path(), "b.txt", b"beta");
    write_file(tmp.path(), "c.txt", b"gamma");
    // Symlink → alpha (file). Walk skip etmeli + warn log.
    let target = tmp.path().join("a.txt");
    let link = tmp.path().join("link_to_a");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let entries = enumerate_folder(tmp.path()).unwrap();
    let files: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .collect();
    assert_eq!(files.len(), 3, "symlink skip edilmeli; got {entries:#?}");
    let names: Vec<&str> = files.iter().map(|e| e.relative_path.as_str()).collect();
    assert!(names.contains(&"a.txt"));
    assert!(names.contains(&"b.txt"));
    assert!(names.contains(&"c.txt"));
    assert!(
        !names.contains(&"link_to_a"),
        "symlink manifest'e SIZMAMALI"
    );
}

/// PR-C invariant 2 — depth > MAX_FOLDER_DEPTH (32) reject.
///
/// 33-deep nested directory walk başarısız olmalı; receiver tarafında DoS /
/// path-traversal guard.
#[test]
fn enumerate_folder_depth_exceeded_errors() {
    let tmp = tempdir().unwrap();
    let mut path = tmp.path().to_path_buf();
    for i in 0..33 {
        path = path.join(format!("d{i}"));
    }
    fs::create_dir_all(&path).unwrap();
    let r = enumerate_folder(tmp.path());
    assert!(
        matches!(r, Err(EnumerateError::DepthExceeded { .. })),
        "depth 33 reject beklenirken: {r:?}"
    );
}

/// PR-C invariant 3 — entry count > MAX_FOLDER_ENTRIES (10 000) reject.
///
/// Receiver memory + manifest size guard.
#[test]
fn enumerate_folder_entry_count_exceeded_errors() {
    let tmp = tempdir().unwrap();
    // 10 001 file flat tek dizinde.
    for i in 0..=MAX_FOLDER_ENTRIES {
        let p = tmp.path().join(format!("f{i:05}.bin"));
        fs::write(&p, b"x").unwrap();
    }
    let r = enumerate_folder(tmp.path());
    assert!(
        matches!(r, Err(EnumerateError::EntryCountExceeded { .. })),
        "entry count > {MAX_FOLDER_ENTRIES} reject beklenirken: {r:?}"
    );
}

/// PR-C invariant 4 — manifest entries içindeki SHA-256, file body'sinin
/// streaming SHA-256'sıyla **byte-exact** eşleşmeli.
///
/// Receiver per-entry verify aşamasında bu hash'leri kullanır
/// (`docs/protocol/folder-payload.md` §6 step 5).
#[test]
fn build_manifest_per_file_sha256_correct() {
    let tmp = tempdir().unwrap();
    write_file(tmp.path(), "alpha.txt", b"hello world");
    write_file(tmp.path(), "beta.txt", b"second body");
    let entries = enumerate_folder(tmp.path()).unwrap();
    let manifest = build_manifest(tmp.path(), &entries).unwrap();
    manifest.validate().unwrap();

    for entry in &manifest.entries {
        if let ManifestEntry::File { path, sha256, .. } = entry {
            let mut h = Sha256::new();
            let body = match path.as_str() {
                "alpha.txt" => b"hello world".as_slice(),
                "beta.txt" => b"second body".as_slice(),
                other => panic!("beklenmeyen path: {other}"),
            };
            h.update(body);
            let expected = hex_lower(&h.finalize());
            assert_eq!(sha256, &expected, "{path} hash uymuyor");
        }
    }
}

/// PR-C invariant 5 — bundle_total_size = 16 + manifest_len +
/// sum(file_sizes) + 32 (`docs/protocol/folder-payload.md` §2 layout).
///
/// `Introduction.FileMetadata.size` bunu kullanır; receiver tarafında
/// `concat_data_len` checked-arithmetic ile bu değerden türetilir.
#[test]
fn bundle_total_size_calculation() {
    let tmp = tempdir().unwrap();
    write_file(tmp.path(), "x.bin", b"1234567890"); // 10 byte
    write_file(tmp.path(), "y.bin", b"abcdef"); // 6 byte
    let entries = enumerate_folder(tmp.path()).unwrap();
    let manifest = build_manifest(tmp.path(), &entries).unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    let total = bundle_total_size(manifest_json.len(), &entries).unwrap();
    let expected = HEADER_LEN as u64 + manifest_json.len() as u64 + 10 + 6 + TRAILER_LEN as u64;
    assert_eq!(
        total, expected,
        "bundle_total_size hesabı yanlış (header={HEADER_LEN}, manifest_len={}, files=16, trailer={TRAILER_LEN})",
        manifest_json.len()
    );
}

/// PR-C invariant 6 — sender'ın emit edeceği tam bundle byte stream'i,
/// `BundleReader::open` ile parse edilebilmeli + trailer verify geçmeli.
///
/// Bu test `send_folder_bundle` private async fn'ün byte-exact in-memory
/// simülasyonudur (`BundleWriter::new` then header then manifest then per-file
/// body then finalize trailer). Sonrasında bytes diske yazılır,
/// `BundleReader::open` parse + manifest_json round-trip karşılaştırılır.
#[test]
fn send_folder_bundle_full_loopback_decode_matches_manifest() {
    let tmp = tempdir().unwrap();
    write_file(tmp.path(), "alpha.txt", b"alpha-body-content");
    write_file(tmp.path(), "subdir/beta.txt", b"beta-content-2");
    let entries = enumerate_folder(tmp.path()).unwrap();
    let manifest = build_manifest(tmp.path(), &entries).unwrap();
    manifest.validate().unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();

    // BundleWriter — sender pipeline'ının byte-exact aynısı.
    let mut writer = BundleWriter::new(&manifest_json).unwrap();
    let mut bundle: Vec<u8> = Vec::new();
    bundle.extend_from_slice(&writer.header_bytes());
    bundle.extend_from_slice(&manifest_json);

    // Per-entry body — dizin atlanır, file order manifest sırasıyla aynı
    // (enumerate deterministic).
    for entry in &entries {
        if entry.kind != EntryKind::File {
            continue;
        }
        let body = fs::read(&entry.absolute_path).unwrap();
        writer.update(&body);
        bundle.extend_from_slice(&body);
    }
    let trailer = writer.finalize();
    bundle.extend_from_slice(&trailer);

    // Disk'e yaz + BundleReader ile parse.
    let tmp_bundle = NamedTempFile::new().unwrap();
    fs::write(tmp_bundle.path(), &bundle).unwrap();
    let reader = BundleReader::open(tmp_bundle.path()).expect("BundleReader::open success");
    assert_eq!(reader.manifest_json(), manifest_json.as_slice());
    assert_eq!(reader.bundle_len(), bundle.len() as u64);
    // concat_data_len = sum of file sizes (alpha 18 + beta 14 = 32).
    assert_eq!(reader.concat_data_len(), 18 + 14);

    // Manifest'i bytes'tan tekrar parse + spec uygunluk.
    let parsed: BundleManifest = serde_json::from_slice(reader.manifest_json()).unwrap();
    assert_eq!(parsed, manifest);
}

/// PR-C invariant 7 — `Introduction.attachment_hash` = `manifest_sha256[0..8]`
/// BE i64 (`docs/protocol/folder-payload.md` §4.1). Receiver bu değeri
/// post-bundle `manifest_json` re-hash sonucu ile karşılaştırır; mismatch
/// `Atomic-reject`.
#[test]
fn attachment_hash_matches_manifest_sha256_prefix() {
    let tmp = tempdir().unwrap();
    write_file(tmp.path(), "f.bin", b"deterministic-body");
    let entries = enumerate_folder(tmp.path()).unwrap();
    let manifest = build_manifest(tmp.path(), &entries).unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();

    let attachment_hash = manifest.attachment_hash_i64().unwrap();

    // Bağımsız hesap: SHA-256(manifest_json)[0..8] BE i64.
    let mut h = Sha256::new();
    h.update(&manifest_json);
    let digest: [u8; 32] = h.finalize().into();
    let prefix: [u8; 8] = digest[0..8].try_into().unwrap();
    let expected = i64::from_be_bytes(prefix);
    assert_eq!(
        attachment_hash, expected,
        "Introduction.attachment_hash != SHA-256(manifest_json)[0..8] BE i64"
    );
}

/// PR-C invariant 8 — capability inactive yolda flatten fallback semantiği:
/// directory entries `concat_data`'ya katkı vermez (size = 0), file
/// basename'leri tekildir, sender bunları individual file plan'larına
/// dönüştürebilir.
///
/// `flatten_folder_to_files` sender.rs içinde private; testte enumerate
/// çıktısı, `bundle_total_size`'in directory'leri sıfır byte saydığı,
/// ve file count'un beklenen değer olduğu doğrulanarak fallback
/// invariant'ı sabitlenir.
#[test]
fn send_folder_bundle_capability_inactive_falls_back_to_flatten() {
    let tmp = tempdir().unwrap();
    // 2 file + 2 directory (boş alt klasör + nested sub).
    write_file(tmp.path(), "top.txt", b"top-body");
    write_file(tmp.path(), "subdir1/inner.txt", b"inner-body");
    fs::create_dir_all(tmp.path().join("subdir2_empty")).unwrap();

    let entries = enumerate_folder(tmp.path()).unwrap();
    let files: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .collect();
    let dir_count = entries
        .iter()
        .filter(|e| e.kind == EntryKind::Directory)
        .count();

    // 2 file (top.txt + subdir1/inner.txt), 2 directory (subdir1, subdir2_empty).
    assert_eq!(files.len(), 2, "file count flatten için sayılır");
    assert_eq!(dir_count, 2, "directory entries manifest'te kalır");

    // bundle_total_size dir entries için 0 byte sayar — sadece file size'ları
    // toplanır.
    let manifest = build_manifest(tmp.path(), &entries).unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    let total = bundle_total_size(manifest_json.len(), &entries).unwrap();
    let file_size_sum: u64 = files.iter().map(|e| e.size).sum();
    let expected =
        HEADER_LEN as u64 + manifest_json.len() as u64 + file_size_sum + TRAILER_LEN as u64;
    assert_eq!(
        total, expected,
        "directory entries body byte katkısı SIFIR olmalı"
    );

    // Capability inactive path'te sender flat akışa düşer; flat plan'da
    // yalnızca file basename'leri kullanılır (sub-directory yapısı kayıp).
    // Bu invariant'ı assert etmek için file basename'lerinin map'ini kur:
    let basenames: Vec<&str> = files
        .iter()
        .map(|e| {
            std::path::Path::new(&e.relative_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("dosya")
        })
        .collect();
    assert!(basenames.contains(&"top.txt"));
    assert!(basenames.contains(&"inner.txt"));
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
