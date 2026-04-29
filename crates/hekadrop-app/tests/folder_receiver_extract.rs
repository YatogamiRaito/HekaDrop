// Test/bench dosyası — production lint'leri test idiomatik kullanımı bozmasın.
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
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::similar_names
)]

//! RFC-0005 PR-D — receiver-side bundle parse + atomic-reject extract
//! invariant'ları.
//!
//! Bu test dosyası `hekadrop::folder::extract::extract_bundle` public API'sini
//! ve `PayloadAssembler::register_bundle_marker` /
//! `connection::FOLDER_BUNDLE_MIME` Introduction-handler kontratını sabitler.
//!
//! Kapsam (10 test):
//! 1. happy path 3 file extract — per-file SHA-256 + final byte-by-byte verify.
//! 2. attachment_hash mismatch → reject + temp cleanup.
//! 3. manifest path = "../etc/passwd" → reject (manifest validate).
//! 4. per-file SHA-256 mismatch → atomic-reject (tüm temp + .bundle silinir,
//!    Downloads'a hiçbir entry sızmaz).
//! 5. parent symlink (staging dir as symlink) → cleanup + fresh mkdir +
//!    extract OK (defansif kontrol).
//! 6. Downloads collision (`MyFolder` mevcut) → `MyFolder (2)` rename.
//! 7. directory entries oluşturulur (1 file + 2 directory).
//! 8. empty folder + 1 directory entry → empty folder extract.
//! 9. PayloadAssembler bundle marker register/take roundtrip — Introduction
//!    handler simülasyonu.
//! 10. PayloadAssembler bundle marker capability inactive bypass —
//!     `take_bundle_marker` None döner, mevcut individual file akışı.

use hekadrop::folder::{
    extract_bundle, BundleManifest, BundleWriter, ExtractError, ManifestEntry, ManifestError,
    MANIFEST_VERSION,
};
use hekadrop::payload::{BundleMarker, PayloadAssembler};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

mod common;

fn sha_hex(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    let digest: [u8; 32] = h.finalize().into();
    hex::encode(digest)
}

fn write_bundle(path: &Path, manifest_json: &[u8], bodies: &[&[u8]]) {
    let mut writer = BundleWriter::new(manifest_json).unwrap();
    let header_bytes = writer.header_bytes();
    let mut f = fs::File::create(path).unwrap();
    f.write_all(&header_bytes).unwrap();
    f.write_all(manifest_json).unwrap();
    for body in bodies {
        f.write_all(body).unwrap();
        writer.update(body);
    }
    let trailer = writer.finalize();
    f.write_all(&trailer).unwrap();
    f.sync_all().unwrap();
}

fn build_manifest(root_name: &str, entries: Vec<ManifestEntry>) -> (BundleManifest, Vec<u8>) {
    let total = u32::try_from(entries.len()).unwrap();
    let m = BundleManifest {
        version: MANIFEST_VERSION,
        root_name: root_name.to_owned(),
        total_entries: total,
        entries,
        created_utc: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    };
    let json = serde_json::to_vec(&m).unwrap();
    (m, json)
}

/// PR-D invariant 1 — happy path: 3-file bundle extract OK, per-file
/// SHA-256 ve final byte-by-byte içerik verify.
#[test]
fn extract_bundle_happy_path_3_files() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-1234.bundle");
    let (m, json) = build_manifest(
        "myfolder",
        vec![
            ManifestEntry::File {
                path: "doc1.txt".to_owned(),
                size: 11,
                sha256: sha_hex(b"hello world"),
                mode: None,
                mtime: None,
            },
            ManifestEntry::File {
                path: "sub/doc2.bin".to_owned(),
                size: 4,
                sha256: sha_hex(&[0xDE, 0xAD, 0xBE, 0xEF]),
                mode: None,
                mtime: None,
            },
            ManifestEntry::File {
                path: "sub/doc3.txt".to_owned(),
                size: 5,
                sha256: sha_hex(b"third"),
                mode: None,
                mtime: None,
            },
        ],
    );
    write_bundle(
        &bundle,
        &json,
        &[b"hello world", &[0xDE, 0xAD, 0xBE, 0xEF], b"third"],
    );
    let prefix = m.attachment_hash_i64().unwrap();
    let result = extract_bundle(&bundle, prefix, downloads.path(), "1234").unwrap();

    assert_eq!(result.file_count, 3);
    assert_eq!(result.total_entries, 3);
    assert_eq!(result.final_path, downloads.path().join("myfolder"));
    assert_eq!(
        fs::read(result.final_path.join("doc1.txt")).unwrap(),
        b"hello world"
    );
    assert_eq!(
        fs::read(result.final_path.join("sub/doc2.bin")).unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert_eq!(
        fs::read(result.final_path.join("sub/doc3.txt")).unwrap(),
        b"third"
    );
    // Cleanup invariants:
    assert!(!bundle.exists(), ".bundle silinmeliydi");
    assert!(
        !downloads.path().join(".hekadrop-extract-1234").exists(),
        "staging dir silinmeliydi"
    );
}

/// PR-D invariant 2 — attachment_hash mismatch reject + temp cleanup.
#[test]
fn extract_bundle_attachment_hash_mismatch_rejects() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-aa.bundle");
    let (_m, json) = build_manifest(
        "x",
        vec![ManifestEntry::File {
            path: "a.txt".to_owned(),
            size: 1,
            sha256: sha_hex(b"y"),
            mode: None,
            mtime: None,
        }],
    );
    write_bundle(&bundle, &json, &[b"y"]);

    let r = extract_bundle(&bundle, 0xCAFE_BABE, downloads.path(), "aa");
    assert!(
        matches!(r, Err(ExtractError::AttachmentHashMismatch { .. })),
        "got {r:?}"
    );
    // Cleanup
    assert!(!bundle.exists());
    assert!(!downloads.path().join(".hekadrop-extract-aa").exists());
    assert!(!downloads.path().join("x").exists());
}

/// PR-D invariant 3 — manifest entry path "../etc/passwd" → reject;
/// manifest validate'te yakalanır, extract pipeline'a ulaşmaz.
#[test]
fn extract_bundle_traversal_path_rejects() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-tr.bundle");
    let (m, json) = build_manifest(
        "rt",
        vec![ManifestEntry::File {
            path: "../etc/passwd".to_owned(),
            size: 4,
            sha256: sha_hex(b"evil"),
            mode: None,
            mtime: None,
        }],
    );
    write_bundle(&bundle, &json, &[b"evil"]);
    let prefix = m.attachment_hash_i64().unwrap();

    let r = extract_bundle(&bundle, prefix, downloads.path(), "tr");
    assert!(
        matches!(r, Err(ExtractError::Manifest(ManifestError::Path(_)))),
        "got {r:?}"
    );
    // Hiçbir entry yazılmamış olmalı.
    let parent = downloads.path().parent().unwrap();
    assert!(!parent.join("etc/passwd").exists());
    assert!(!downloads.path().join("rt").exists());
    assert!(!bundle.exists());
}

/// PR-D invariant 4 — per-file SHA-256 mismatch atomic-reject:
/// 3 file, 2.dosya body tampered. Extract pipeline 2.dosyayı doğrularken
/// `EntrySha256Mismatch` döner; tüm staging + .bundle silinir, Downloads'a
/// hiçbir entry (1.dosya bile) sızmaz.
#[test]
fn extract_bundle_per_file_sha256_mismatch_rejects_all() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-mm.bundle");
    // Manifest 2.dosya için yanlış sha256 beyan eder; gerçek body "two".
    let (m, json) = build_manifest(
        "atomic",
        vec![
            ManifestEntry::File {
                path: "one.txt".to_owned(),
                size: 3,
                sha256: sha_hex(b"one"),
                mode: None,
                mtime: None,
            },
            ManifestEntry::File {
                path: "two.txt".to_owned(),
                size: 3,
                sha256: sha_hex(b"XXX"), // Wrong!
                mode: None,
                mtime: None,
            },
            ManifestEntry::File {
                path: "three.txt".to_owned(),
                size: 5,
                sha256: sha_hex(b"three"),
                mode: None,
                mtime: None,
            },
        ],
    );
    write_bundle(&bundle, &json, &[b"one", b"two", b"three"]);
    let prefix = m.attachment_hash_i64().unwrap();

    let r = extract_bundle(&bundle, prefix, downloads.path(), "mm");
    assert!(
        matches!(r, Err(ExtractError::EntrySha256Mismatch { .. })),
        "got {r:?}"
    );
    // Atomic-reject: hiçbir entry final hedefte olmamalı.
    assert!(!downloads.path().join("atomic").exists());
    assert!(!downloads.path().join("atomic/one.txt").exists());
    assert!(!downloads.path().join(".hekadrop-extract-mm").exists());
    assert!(!bundle.exists());
}

/// PR-D invariant 5 — staging dir parent'ı symlink (önceki crash artığı):
/// extract pipeline staging exists + symlink durumunu silinmiş gibi temizler
/// + fresh mkdir yapar; downstream extract OK.
#[cfg(unix)]
#[test]
fn extract_bundle_parent_symlink_cleared_then_extract_ok() {
    let downloads = tempdir().unwrap();
    let real_target = tempdir().unwrap();
    // Önceden var olan staging symlink (önceki crash artığı simülasyonu).
    let staging_link = downloads.path().join(".hekadrop-extract-sl");
    std::os::unix::fs::symlink(real_target.path(), &staging_link).unwrap();

    let bundle = downloads.path().join(".hekadrop-temp-sl.bundle");
    let (m, json) = build_manifest(
        "okfolder",
        vec![ManifestEntry::File {
            path: "a.txt".to_owned(),
            size: 1,
            sha256: sha_hex(b"x"),
            mode: None,
            mtime: None,
        }],
    );
    write_bundle(&bundle, &json, &[b"x"]);
    let prefix = m.attachment_hash_i64().unwrap();

    let result = extract_bundle(&bundle, prefix, downloads.path(), "sl").unwrap();
    assert_eq!(result.final_path, downloads.path().join("okfolder"));
    assert_eq!(fs::read(result.final_path.join("a.txt")).unwrap(), b"x");
    // Real target dizinine fail-out olmadı (symlink temizlenmişti).
    let real_files: Vec<PathBuf> = fs::read_dir(real_target.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(real_files.is_empty(), "real_target dokunulmamış olmalı");
}

/// PR-D invariant 6 — Downloads'da `MyFolder` mevcut → `MyFolder (2)`
/// collision-suffix.
#[test]
fn extract_bundle_unique_downloads_collision() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-cc.bundle");
    let (m, json) = build_manifest(
        "MyFolder",
        vec![ManifestEntry::File {
            path: "f.txt".to_owned(),
            size: 1,
            sha256: sha_hex(b"a"),
            mode: None,
            mtime: None,
        }],
    );
    write_bundle(&bundle, &json, &[b"a"]);
    let prefix = m.attachment_hash_i64().unwrap();

    // Önce mevcut bir dizin oluştur.
    fs::create_dir_all(downloads.path().join("MyFolder")).unwrap();

    let result = extract_bundle(&bundle, prefix, downloads.path(), "cc").unwrap();
    assert_eq!(result.final_path, downloads.path().join("MyFolder (2)"));
    assert_eq!(fs::read(result.final_path.join("f.txt")).unwrap(), b"a");
    // Original "MyFolder" dokunulmadı.
    assert!(downloads.path().join("MyFolder").is_dir());
}

/// PR-D invariant 7 — manifest 1 file + 2 directory; her directory entry
/// extract sonrası dizin olarak oluşur.
#[test]
fn extract_bundle_directory_entries_created() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-dd.bundle");
    let (m, json) = build_manifest(
        "tree",
        vec![
            ManifestEntry::Directory {
                path: "alpha".to_owned(),
                mode: None,
                mtime: None,
            },
            ManifestEntry::Directory {
                path: "alpha/beta".to_owned(),
                mode: None,
                mtime: None,
            },
            ManifestEntry::File {
                path: "alpha/beta/leaf.txt".to_owned(),
                size: 4,
                sha256: sha_hex(b"leaf"),
                mode: None,
                mtime: None,
            },
        ],
    );
    write_bundle(&bundle, &json, &[b"leaf"]);
    let prefix = m.attachment_hash_i64().unwrap();

    let result = extract_bundle(&bundle, prefix, downloads.path(), "dd").unwrap();
    assert_eq!(result.file_count, 1);
    assert_eq!(result.total_entries, 3);
    assert!(result.final_path.join("alpha").is_dir());
    assert!(result.final_path.join("alpha/beta").is_dir());
    assert_eq!(
        fs::read(result.final_path.join("alpha/beta/leaf.txt")).unwrap(),
        b"leaf"
    );
}

/// PR-D invariant 8 — sıfır file + 1 directory entry → empty folder extract.
#[test]
fn extract_bundle_empty_folder_with_root_directory_entry() {
    let downloads = tempdir().unwrap();
    let bundle = downloads.path().join(".hekadrop-temp-ee.bundle");
    let (m, json) = build_manifest(
        "empty",
        vec![ManifestEntry::Directory {
            path: "inner".to_owned(),
            mode: None,
            mtime: None,
        }],
    );
    write_bundle(&bundle, &json, &[]);
    let prefix = m.attachment_hash_i64().unwrap();

    let result = extract_bundle(&bundle, prefix, downloads.path(), "ee").unwrap();
    assert_eq!(result.file_count, 0);
    assert_eq!(result.total_entries, 1);
    assert!(result.final_path.is_dir());
    assert!(result.final_path.join("inner").is_dir());
    // Inner dizin boş.
    let inner_entries: Vec<_> = fs::read_dir(result.final_path.join("inner"))
        .unwrap()
        .collect();
    assert!(inner_entries.is_empty());
}

/// PR-D invariant 9 — `PayloadAssembler::register_bundle_marker` /
/// `take_bundle_marker` roundtrip. Introduction handler simülasyonu:
/// MIME bundle + capability aktif → register; finalize aşamasında take.
#[test]
fn bundle_marker_register_and_take_roundtrip() {
    let mut a = PayloadAssembler::new();
    let pid = 0xABCD_i64;
    let downloads = tempdir().unwrap();
    let marker = BundleMarker {
        expected_manifest_sha256_prefix: 0xDEAD_BEEF,
        extract_root_dir: downloads.path().to_path_buf(),
        session_id_hex_lower: "1122334455667788".to_owned(),
    };
    assert!(!a.has_bundle_marker(pid));
    a.register_bundle_marker(pid, marker.clone());
    assert!(a.has_bundle_marker(pid));

    let taken = a.take_bundle_marker(pid).unwrap();
    assert_eq!(taken.expected_manifest_sha256_prefix, 0xDEAD_BEEF);
    assert_eq!(taken.extract_root_dir, downloads.path());
    assert_eq!(taken.session_id_hex_lower, "1122334455667788");
    // Idempotent take — ikinci take None.
    assert!(a.take_bundle_marker(pid).is_none());
    assert!(!a.has_bundle_marker(pid));
}

/// PR-D invariant 10 — capability inactive simülasyonu: bundle marker
/// register edilmez (Introduction handler `folder_active` false ise zaten
/// register etmez); `take_bundle_marker` None döner ve mevcut individual
/// file akışı bozulmadan devam eder. Burada doğrudan API: marker
/// register edilmemişse `take` None.
#[test]
fn bundle_marker_capability_inactive_falls_back() {
    let mut a = PayloadAssembler::new();
    let pid = 0xFFFF_i64;
    // Capability inactive simülasyonu — register hiç çağrılmadı.
    assert!(!a.has_bundle_marker(pid));
    assert!(a.take_bundle_marker(pid).is_none());
    // Cancel sonrası da None (eski marker leak'i yok).
    a.cancel(pid);
    assert!(a.take_bundle_marker(pid).is_none());
}
