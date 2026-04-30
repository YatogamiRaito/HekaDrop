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
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments
)]

//! RFC-0005 PR-E — `chunk-HMAC` (RFC-0003) + RESUME_V1 (RFC-0004) bundle
//! akışı entegrasyon testleri.
//!
//! Bu test dosyası bundle byte stream'inin (tek `payload_id` altında çoklu
//! `PayloadTransferFrame{File}` chunk + her chunk'tan sonra `ChunkIntegrity`
//! envelope) mevcut chunk-HMAC + RESUME_V1 pipeline'ından geçişini doğrular.
//! Spec referansları:
//!   - `docs/protocol/folder-payload.md` §4 — bundle MIME marker
//!   - RFC-0003 chunk-hmac.md §1.2 — storage corruption early-abort
//!   - RFC-0004 resume.md §3 — sequence diagram, mid-flight resume
//!
//! Kapsam (5 test):
//! 1. `bundle_chunk_hmac_per_chunk_verify_passes` — sender bundle bytes
//!    chunk'lara split, her chunk için tag verify ok; finalize sonrası
//!    `take_bundle_marker` → `extract_bundle` happy path.
//! 2. `bundle_chunk_hmac_tampered_chunk_rejects_bundle` — orta chunk wire'da
//!    tampered, `verify_chunk_tag` fail → bundle reject (cancel) → diskte
//!    `.bundle` partial silinir + extract pipeline tetiklenmez.
//! 3. `bundle_resume_after_mid_stream_disconnect_continues` — sender 50%
//!    bundle gönder, receiver "disconnect" simülasyonu (`.meta` checkpoint
//!    + assembler drop); reconnect → fresh assembler `enable_resume_with_offset`
//!    + kalan chunk'lar verify edilir + finalize → extract OK.
//! 4. `bundle_resume_with_chunk_hmac_full_pipeline` — resume + chunk-HMAC
//!    birlikte: mid-stream kes, reconnect, son chunk verify, extract OK,
//!    final byte içerik doğrulaması.
//! 5. `bundle_resume_metadata_dest_path_persisted` — `.meta` `dest_path`
//!    bundle path'i içeriyor (PR-G: `meta.dest_path` round-trip); reconnect
//!    yolunda receiver doğru bundle path'e register edebilir
//!    (`PartialMeta::load` + alan kontrolü).

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use chrono::Utc;
use hekadrop::folder::{
    build_manifest, enumerate_folder, extract_bundle, BundleManifest, BundleWriter, EntryKind,
};
use hekadrop::location::nearby::connections::{
    payload_transfer_frame::{
        payload_header::PayloadType as PbPayloadType, PayloadChunk, PayloadHeader,
    },
    PayloadTransferFrame,
};
use hekadrop::payload::{BundleMarker, CompletedPayload, PayloadAssembler};
use hekadrop::resume::{self, meta_filename, partial_dir, session_id_i64, PartialMeta, CHUNK_SIZE};
use hekadrop_core::chunk_hmac::{build_chunk_integrity, compute_tag, derive_chunk_hmac_key};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

mod common;

// -----------------------------------------------------------------------------
// Test infrastructure (TempHome — partial_dir() HOME altına yazar)
// -----------------------------------------------------------------------------

static HOME_LOCK: Mutex<()> = Mutex::new(());

fn unique_label(name: &str) -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("hd-folderhmac-{name}-{pid}-{nanos}")
}

struct TempHome {
    dir: std::path::PathBuf,
    saved: Option<std::ffi::OsString>,
    key: &'static str,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl TempHome {
    fn new() -> Self {
        let guard = HOME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join(unique_label("home"));
        fs::create_dir_all(&dir).expect("temp home mkdir");
        let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let saved = std::env::var_os(key);
        // SAFETY: test sequenced via HOME_LOCK; tek thread bu noktada HOME yazar.
        unsafe {
            std::env::set_var(key, &dir);
        };
        Self {
            dir,
            saved,
            key,
            _guard: guard,
        }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // SAFETY: HOME_LOCK hâlâ tutuluyor, tek thread.
        unsafe {
            if let Some(v) = self.saved.take() {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// -----------------------------------------------------------------------------
// Bundle byte stream helpers
// -----------------------------------------------------------------------------

fn write_file(dir: &Path, rel: &str, body: &[u8]) {
    let full = dir.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(&full).unwrap();
    f.write_all(body).unwrap();
}

/// Sender'ın `send_folder_bundle` ile emit edeceği byte-exact bundle stream'i
/// in-memory üret — `(bundle_bytes, manifest)`.
fn make_bundle_bytes(src_dir: &Path) -> (Vec<u8>, BundleManifest) {
    let entries = enumerate_folder(src_dir).unwrap();
    let manifest = build_manifest(src_dir, &entries).unwrap();
    manifest.validate().unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();

    let mut writer = BundleWriter::new(&manifest_json).unwrap();
    let mut bundle: Vec<u8> = Vec::new();
    bundle.extend_from_slice(&writer.header_bytes());
    bundle.extend_from_slice(&manifest_json);
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
    (bundle, manifest)
}

/// Bundle byte stream'i `chunk_size`'lık parçalara böl. Sender pipeline'ı
/// `(offset, body, last_chunk_flag)` üçlüsü emit eder.
fn split_bundle_chunks(bundle: &[u8], chunk_size: usize) -> Vec<(i64, Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut off: i64 = 0;
    let total = bundle.len();
    let mut consumed = 0;
    while consumed < total {
        let end = (consumed + chunk_size).min(total);
        let body: Vec<u8> = bundle[consumed..end].to_vec();
        let is_last = end == total;
        let body_len = body.len() as i64;
        out.push((off, body, is_last));
        off += body_len;
        consumed = end;
    }
    if out.is_empty() {
        // Empty bundle pratikte yok — defensive: tek empty terminator.
        out.push((0, Vec::new(), true));
    }
    out
}

fn make_file_frame(
    payload_id: i64,
    total_size: i64,
    offset: i64,
    body: &[u8],
    last: bool,
) -> PayloadTransferFrame {
    PayloadTransferFrame {
        packet_type: None,
        payload_header: Some(PayloadHeader {
            id: Some(payload_id),
            r#type: Some(PbPayloadType::File as i32),
            total_size: Some(total_size),
            is_sensitive: None,
            file_name: None,
            parent_folder: None,
            last_modified_timestamp_millis: None,
        }),
        payload_chunk: Some(PayloadChunk {
            flags: Some(if last { 1 } else { 0 }),
            offset: Some(offset),
            body: Some(body.to_vec().into()),
            index: None,
        }),
        control_message: None,
    }
}

/// Bundle stream'i chunk-HMAC pipeline'ında tek bir assembler ile baştan sona
/// aktar. İlk `cutoff_chunks` chunk'tan sonra durdur (resume simülasyonu)
/// ve son durumu döndür: `(written_bytes, last_chunk_index, last_tag_b64)`.
async fn ingest_bundle_until_cutoff(
    asm: &mut PayloadAssembler,
    key: &[u8; 32],
    payload_id: i64,
    total_size: i64,
    chunks: &[(i64, Vec<u8>, bool)],
    cutoff: usize,
) -> (i64, i64, String) {
    let mut last_tag_b64 = String::new();
    let mut written: i64 = 0;
    for (idx, (offset, body, last)) in chunks.iter().take(cutoff).enumerate() {
        let chunk_index = idx as i64;
        let frame = make_file_frame(payload_id, total_size, *offset, body, *last);
        asm.ingest(&frame).await.expect("ingest ok");
        let tag = compute_tag(key, payload_id, chunk_index, *offset, body).expect("compute_tag");
        last_tag_b64 = BASE64_STD.encode(tag);
        let ci = build_chunk_integrity(payload_id, chunk_index, *offset, body.len(), tag).unwrap();
        let _ = asm.verify_chunk_tag(&ci).await.expect("verify ok");
        written += body.len() as i64;
    }
    let last_idx = (cutoff as i64).saturating_sub(1);
    (written, last_idx, last_tag_b64)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// PR-E invariant 1 — happy path: bundle wire bytes chunk-HMAC pipeline'dan
/// geçer, finalize sonrası `take_bundle_marker` + `extract_bundle` happy path.
#[tokio::test]
async fn bundle_chunk_hmac_per_chunk_verify_passes() {
    let _home = TempHome::new();
    // Source folder → bundle bytes
    let src = tempdir().unwrap();
    write_file(src.path(), "alpha.txt", b"alpha-content-12345");
    write_file(src.path(), "sub/beta.txt", b"beta-content-67890");
    let (bundle_bytes, manifest) = make_bundle_bytes(src.path());
    let total_size = bundle_bytes.len() as i64;
    let attachment_hash = manifest.attachment_hash_i64().unwrap();

    // Receiver: bundle path simülasyonu (gerçek connection.rs path semantiği).
    let downloads = tempdir().unwrap();
    let session_hex = "0123456789abcdef";
    let bundle_path = downloads
        .path()
        .join(format!(".hekadrop-temp-{session_hex}.bundle"));

    // Pipeline kur.
    let key = derive_chunk_hmac_key(&[0xA1u8; 32]);
    let mut asm = PayloadAssembler::new();
    asm.set_chunk_hmac_key(key);
    let payload_id = 1001i64;
    asm.register_file_destination(payload_id, bundle_path.clone())
        .unwrap();
    asm.register_bundle_marker(
        payload_id,
        BundleMarker {
            expected_manifest_sha256_prefix: attachment_hash,
            extract_root_dir: downloads.path().to_path_buf(),
            session_id_hex_lower: session_hex.to_owned(),
        },
    );

    // Bundle'ı 4 KiB chunk'lara böl + tüm pipeline'ı çalıştır.
    let chunks = split_bundle_chunks(&bundle_bytes, 4096);
    let mut completed: Option<CompletedPayload> = None;
    for (idx, (offset, body, last)) in chunks.iter().enumerate() {
        let chunk_index = idx as i64;
        let frame = make_file_frame(payload_id, total_size, *offset, body, *last);
        let _ = asm.ingest(&frame).await.expect("ingest ok");
        let tag = compute_tag(&key, payload_id, chunk_index, *offset, body).unwrap();
        let ci = build_chunk_integrity(payload_id, chunk_index, *offset, body.len(), tag).unwrap();
        if let Some(done) = asm.verify_chunk_tag(&ci).await.unwrap() {
            completed = Some(done);
        }
    }

    let payload = completed.expect("son chunk verify ile finalize beklenir");
    let CompletedPayload::File { id, path, .. } = payload else {
        panic!("File variant beklenir");
    };
    assert_eq!(id, payload_id);
    assert_eq!(path, bundle_path);

    // Finalize dispatch: take_bundle_marker → extract_bundle.
    let marker = asm
        .take_bundle_marker(payload_id)
        .expect("marker register edilmişti");
    let extracted = extract_bundle(
        &bundle_path,
        marker.expected_manifest_sha256_prefix,
        &marker.extract_root_dir,
        &marker.session_id_hex_lower,
    )
    .expect("extract OK");

    // Byte-by-byte verify.
    assert_eq!(extracted.file_count, 2);
    let alpha = fs::read(extracted.final_path.join("alpha.txt")).unwrap();
    let beta = fs::read(extracted.final_path.join("sub/beta.txt")).unwrap();
    assert_eq!(alpha, b"alpha-content-12345");
    assert_eq!(beta, b"beta-content-67890");

    // Cleanup invariants — extract_bundle .bundle'ı siler.
    assert!(!bundle_path.exists());
}

/// PR-E invariant 2 — orta chunk wire'da tampered: `verify_chunk_tag` fail →
/// caller cancel → diskteki `.bundle` partial silinir, extract pipeline
/// tetiklenmez (Downloads'a hiçbir entry sızmaz).
#[tokio::test]
async fn bundle_chunk_hmac_tampered_chunk_rejects_bundle() {
    let _home = TempHome::new();
    let src = tempdir().unwrap();
    write_file(src.path(), "f1.txt", b"one-body-aaaa");
    write_file(src.path(), "f2.txt", b"two-body-bbbb");
    write_file(src.path(), "f3.txt", b"three-body-cc");
    let (bundle_bytes, manifest) = make_bundle_bytes(src.path());
    let total_size = bundle_bytes.len() as i64;
    let attachment_hash = manifest.attachment_hash_i64().unwrap();

    let downloads = tempdir().unwrap();
    let session_hex = "abcdef0011223344";
    let bundle_path = downloads
        .path()
        .join(format!(".hekadrop-temp-{session_hex}.bundle"));

    let key = derive_chunk_hmac_key(&[0xB2u8; 32]);
    let mut asm = PayloadAssembler::new();
    asm.set_chunk_hmac_key(key);
    let payload_id = 2002i64;
    asm.register_file_destination(payload_id, bundle_path.clone())
        .unwrap();
    asm.register_bundle_marker(
        payload_id,
        BundleMarker {
            expected_manifest_sha256_prefix: attachment_hash,
            extract_root_dir: downloads.path().to_path_buf(),
            session_id_hex_lower: session_hex.to_owned(),
        },
    );

    let chunks = split_bundle_chunks(&bundle_bytes, 64);
    assert!(
        chunks.len() >= 3,
        "best-effort: en az 3 chunk için tampering anlamlı"
    );

    // 1.chunk OK; 2.chunk wire'da body değiştir + tag orijinal body için
    // hesaplandı (storage corruption arası decrypt + buffer mutation).
    let mid = 1usize;
    for (idx, (offset, body, last)) in chunks.iter().enumerate() {
        let chunk_index = idx as i64;
        if idx == mid {
            // Wire'a tampered body, tag orijinal body'den hesaplanmış.
            let mut tampered = body.clone();
            tampered[0] ^= 0xFF;
            let frame = make_file_frame(payload_id, total_size, *offset, &tampered, *last);
            let _ = asm.ingest(&frame).await.expect("ingest ok (pending)");
            let tag = compute_tag(&key, payload_id, chunk_index, *offset, body).unwrap();
            let ci =
                build_chunk_integrity(payload_id, chunk_index, *offset, body.len(), tag).unwrap();
            let err = asm
                .verify_chunk_tag(&ci)
                .await
                .expect_err("tampered body → mismatch");
            let s = err.to_string();
            assert!(
                s.contains("verify fail") || s.contains("HMAC") || s.contains("mismatch"),
                "verify fail mesajı beklenir: {s}"
            );
            // Spec §9: caller cancel(payload_id) çağırmalı.
            asm.cancel(payload_id);
            break;
        }
        let frame = make_file_frame(payload_id, total_size, *offset, body, *last);
        let _ = asm.ingest(&frame).await.expect("ingest ok");
        let tag = compute_tag(&key, payload_id, chunk_index, *offset, body).unwrap();
        let ci = build_chunk_integrity(payload_id, chunk_index, *offset, body.len(), tag).unwrap();
        let _ = asm.verify_chunk_tag(&ci).await.expect("verify ok");
    }

    // Cancel sonrası bundle path silinmeli + bundle marker temizlenmeli.
    assert!(
        !bundle_path.exists(),
        "tampered → .bundle partial silinmeli"
    );
    assert!(
        asm.take_bundle_marker(payload_id).is_none(),
        "cancel sonrası bundle marker leak yok"
    );
    // Downloads'a hiçbir extracted folder yazılmadı.
    let entries: Vec<_> = fs::read_dir(downloads.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    for e in &entries {
        // Yalnız bundle placeholder izine izin verilirdi; o da silindi.
        assert!(
            !e.is_dir() || !e.file_name().unwrap().to_string_lossy().starts_with('.'),
            "Downloads'a extracted folder sızmamalı: {e:?}"
        );
    }
}

/// PR-E invariant 3 — mid-stream disconnect + reconnect → ResumeHint offset →
/// sender baştan rebuild + seek to offset → kalan chunk'lar verify + finalize +
/// extract OK. Bu test fresh assembler ile resume injection (`enable_resume_with_offset`)
/// senaryosunu doğrular.
#[tokio::test]
async fn bundle_resume_after_mid_stream_disconnect_continues() {
    let _home = TempHome::new();
    let src = tempdir().unwrap();
    write_file(src.path(), "doc.txt", b"resume-body-content-deterministic");
    write_file(src.path(), "more.bin", b"second-payload-body-data");
    let (bundle_bytes, manifest) = make_bundle_bytes(src.path());
    let total_size = bundle_bytes.len() as i64;
    let attachment_hash = manifest.attachment_hash_i64().unwrap();

    let downloads = tempdir().unwrap();
    let auth_key = [0x77u8; 32];
    let session_id = session_id_i64(&auth_key);
    let session_hex = format!("{:016x}", session_id as u64);
    let bundle_path = downloads
        .path()
        .join(format!(".hekadrop-temp-{session_hex}.bundle"));

    // Chunk size küçük tutalım ki cut yapalım (32 byte → ~10+ chunk).
    let chunks = split_bundle_chunks(&bundle_bytes, 32);
    assert!(chunks.len() >= 4, "resume için yeterli chunk gerekiyor");
    let cutoff = chunks.len() / 2;

    // ---- Session 1: ilk yarı transfer (chunk-HMAC + resume `.meta`) ----
    let key = derive_chunk_hmac_key(&[0xC3u8; 32]);
    let payload_id = 3003i64;
    let (written, _last_idx, _last_tag) = {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, bundle_path.clone())
            .unwrap();
        asm.enable_resume(
            payload_id,
            session_id,
            "peer-bundle".to_string(),
            "bundle.bundle".to_string(),
        )
        .unwrap();

        let r = ingest_bundle_until_cutoff(&mut asm, &key, payload_id, total_size, &chunks, cutoff)
            .await;
        // Disconnect simulation: assembler drop. .part dosyası diskte kalır,
        // .meta checkpoint ya yazılmıştır ya da yetersiz chunk varsa elle
        // yazalım (spec §3.3 caller best-effort persist).
        let dir = partial_dir().expect("partial_dir");
        let meta_path = dir.join(meta_filename(session_id, payload_id));
        if !meta_path.exists() {
            // Henüz CHECKPOINT_INTERVAL_CHUNKS'a ulaşmadık — manuel persist
            // (gerçek pipeline'da disconnect'ten önceki son checkpoint'e geri düşer;
            // burada test deterministik olsun diye şu anki state'i yazalım).
            let now = Utc::now();
            let meta = PartialMeta {
                version: 1,
                session_id_hex: session_hex.clone(),
                payload_id,
                file_name: "bundle.bundle".to_string(),
                total_size,
                received_bytes: r.0,
                chunk_size: CHUNK_SIZE,
                chunk_hmac_chain_b64: r.2.clone(),
                peer_endpoint_id: "peer-bundle".to_string(),
                created_at: now,
                updated_at: now,
                dest_path: bundle_path.to_string_lossy().into_owned(),
            };
            meta.store_atomic(&dir).unwrap();
        }
        r
    };

    // .part diskte mevcut, boyutu == written.
    let part_size = fs::metadata(&bundle_path).unwrap().len() as i64;
    assert_eq!(part_size, written, "disk partial == cutoff'a kadar yazıldı");

    // ---- Session 2: reconnect — fresh assembler, resume hint inject ----
    let dir = partial_dir().unwrap();
    let meta = PartialMeta::load(&dir, session_id, payload_id)
        .expect("meta load")
        .expect("meta var");
    assert_eq!(meta.received_bytes, written);
    assert_eq!(meta.dest_path, bundle_path.to_string_lossy());

    let next_chunk_idx = meta.received_bytes / i64::from(meta.chunk_size).max(1);
    // Yukarıdaki üretim 32-byte chunk; CHUNK_SIZE 512 KiB. next_chunk_idx
    // resume.md'de "sender chunk size'ından" hesaplanır — burada test bundle
    // chunk size'ı 32 olduğu için sender pipeline kendi kuracaktı. Test
    // amaçlı `cutoff` chunk_index değerini doğrudan inject edeceğiz.
    let _ = next_chunk_idx; // explicit: real path meta.chunk_size kullanır
    let resumed_chunk_index = cutoff as i64;

    let mut asm2 = PayloadAssembler::new();
    asm2.set_chunk_hmac_key(key);
    asm2.register_file_destination(payload_id, bundle_path.clone())
        .unwrap();
    asm2.register_bundle_marker(
        payload_id,
        BundleMarker {
            expected_manifest_sha256_prefix: attachment_hash,
            extract_root_dir: downloads.path().to_path_buf(),
            session_id_hex_lower: session_hex.clone(),
        },
    );
    asm2.enable_resume_with_offset(
        payload_id,
        session_id,
        "peer-bundle".to_string(),
        "bundle.bundle".to_string(),
        meta.received_bytes,
        resumed_chunk_index,
        meta.chunk_hmac_chain_b64.clone(),
    )
    .unwrap();

    // Sender pipeline'ı deterministic — bundle baştan rebuild + seek to offset.
    // Test simülasyonu: kalan chunk'ları cutoff'tan itibaren wire'a koy.
    let mut completed: Option<CompletedPayload> = None;
    for (idx, (offset, body, last)) in chunks.iter().enumerate().skip(cutoff) {
        let chunk_index = idx as i64;
        let frame = make_file_frame(payload_id, total_size, *offset, body, *last);
        let _ = asm2.ingest(&frame).await.expect("ingest ok (resumed)");
        let tag = compute_tag(&key, payload_id, chunk_index, *offset, body).unwrap();
        let ci = build_chunk_integrity(payload_id, chunk_index, *offset, body.len(), tag).unwrap();
        if let Some(done) = asm2.verify_chunk_tag(&ci).await.unwrap() {
            completed = Some(done);
        }
    }
    let payload = completed.expect("resume sonrası finalize beklenir");
    let CompletedPayload::File {
        path,
        total_size: ts,
        ..
    } = payload
    else {
        panic!("File variant beklenir");
    };
    assert_eq!(path, bundle_path);
    assert_eq!(ts, total_size);

    // Finalize dispatch: marker take + extract.
    let marker = asm2.take_bundle_marker(payload_id).expect("marker var");
    let extracted = extract_bundle(
        &bundle_path,
        marker.expected_manifest_sha256_prefix,
        &marker.extract_root_dir,
        &marker.session_id_hex_lower,
    )
    .expect("extract OK");
    assert_eq!(extracted.file_count, 2);
    assert_eq!(
        fs::read(extracted.final_path.join("doc.txt")).unwrap(),
        b"resume-body-content-deterministic"
    );
    assert_eq!(
        fs::read(extracted.final_path.join("more.bin")).unwrap(),
        b"second-payload-body-data"
    );
    // .bundle silindi.
    assert!(!bundle_path.exists());
    // .meta finalize sonrası silindi.
    let meta_path = dir.join(meta_filename(session_id, payload_id));
    assert!(
        !meta_path.exists(),
        "finalize sonrası .meta silinmiş olmalı"
    );
}

/// PR-E invariant 4 — chunk-HMAC + RESUME_V1 birlikte full pipeline:
/// mid-stream kes, son chunk öncesi resume aç + son chunk verify, extract OK.
/// Bu varyant `bundle_resume_after_mid_stream_disconnect_continues` ile bench
/// olarak komplementer; oradaki cut middle, burada cut last-chunk öncesinde
/// → resume PATH'i son chunk verify-finalize'da test edilir.
#[tokio::test]
async fn bundle_resume_with_chunk_hmac_full_pipeline() {
    let _home = TempHome::new();
    let src = tempdir().unwrap();
    write_file(
        src.path(),
        "single.bin",
        b"only-file-with-deterministic-bytes-for-resume",
    );
    let (bundle_bytes, manifest) = make_bundle_bytes(src.path());
    let total_size = bundle_bytes.len() as i64;
    let attachment_hash = manifest.attachment_hash_i64().unwrap();

    let downloads = tempdir().unwrap();
    let auth_key = [0x88u8; 32];
    let session_id = session_id_i64(&auth_key);
    let session_hex = format!("{:016x}", session_id as u64);
    let bundle_path = downloads
        .path()
        .join(format!(".hekadrop-temp-{session_hex}.bundle"));

    // 64-byte chunk → birden fazla chunk; cutoff = chunks.len() - 1
    // (son chunk'tan önce kes).
    let chunks = split_bundle_chunks(&bundle_bytes, 64);
    assert!(chunks.len() >= 2, "en az 2 chunk gerekli");
    let cutoff = chunks.len() - 1;

    let key = derive_chunk_hmac_key(&[0xD4u8; 32]);
    let payload_id = 4004i64;
    // Session 1: cutoff'a kadar.
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, bundle_path.clone())
            .unwrap();
        asm.enable_resume(
            payload_id,
            session_id,
            "peer-x".to_string(),
            "single.bundle".to_string(),
        )
        .unwrap();
        let (written, _, last_tag) =
            ingest_bundle_until_cutoff(&mut asm, &key, payload_id, total_size, &chunks, cutoff)
                .await;
        // Manuel meta persist (test deterministik).
        let dir = partial_dir().unwrap();
        let now = Utc::now();
        let meta = PartialMeta {
            version: 1,
            session_id_hex: session_hex.clone(),
            payload_id,
            file_name: "single.bundle".to_string(),
            total_size,
            received_bytes: written,
            chunk_size: CHUNK_SIZE,
            chunk_hmac_chain_b64: last_tag,
            peer_endpoint_id: "peer-x".to_string(),
            created_at: now,
            updated_at: now,
            dest_path: bundle_path.to_string_lossy().into_owned(),
        };
        meta.store_atomic(&dir).unwrap();
    };

    // Session 2: tek son chunk'ı ekle.
    let dir = partial_dir().unwrap();
    let meta = PartialMeta::load(&dir, session_id, payload_id)
        .unwrap()
        .unwrap();
    let mut asm2 = PayloadAssembler::new();
    asm2.set_chunk_hmac_key(key);
    asm2.register_file_destination(payload_id, bundle_path.clone())
        .unwrap();
    asm2.register_bundle_marker(
        payload_id,
        BundleMarker {
            expected_manifest_sha256_prefix: attachment_hash,
            extract_root_dir: downloads.path().to_path_buf(),
            session_id_hex_lower: session_hex.clone(),
        },
    );
    asm2.enable_resume_with_offset(
        payload_id,
        session_id,
        "peer-x".to_string(),
        "single.bundle".to_string(),
        meta.received_bytes,
        cutoff as i64,
        meta.chunk_hmac_chain_b64.clone(),
    )
    .unwrap();

    let (offset, body, last) = &chunks[cutoff];
    assert!(*last, "cutoff = chunks.len()-1 → last chunk olmalı");
    let chunk_index = cutoff as i64;
    let frame = make_file_frame(payload_id, total_size, *offset, body, *last);
    let _ = asm2.ingest(&frame).await.expect("ingest ok");
    let tag = compute_tag(&key, payload_id, chunk_index, *offset, body).unwrap();
    let ci = build_chunk_integrity(payload_id, chunk_index, *offset, body.len(), tag).unwrap();
    let done = asm2
        .verify_chunk_tag(&ci)
        .await
        .unwrap()
        .expect("son chunk verify → finalize");
    let CompletedPayload::File { path, .. } = done else {
        panic!("File variant beklenir");
    };
    assert_eq!(path, bundle_path);

    let marker = asm2.take_bundle_marker(payload_id).expect("marker var");
    let extracted = extract_bundle(
        &bundle_path,
        marker.expected_manifest_sha256_prefix,
        &marker.extract_root_dir,
        &marker.session_id_hex_lower,
    )
    .expect("extract OK");
    assert_eq!(extracted.file_count, 1);
    assert_eq!(
        fs::read(extracted.final_path.join("single.bin")).unwrap(),
        b"only-file-with-deterministic-bytes-for-resume"
    );
}

/// PR-E invariant 5 — `.meta` `dest_path` bundle path'i içerir (PR-G alanı).
/// Re-handshake yolunda `connection.rs::resolve_resume_path` `meta.dest_path`
/// alanını okur + bundle path ile string-eşitliğini doğrular. Bu test:
///   - Bir bundle için `.meta` yaz (`dest_path` = bundle path).
///   - `PartialMeta::load` ile geri oku, `dest_path` round-trip == orijinal.
///   - Disk üstündeki bundle dosyasının size'ı `meta.received_bytes`'a eşit
///     olduğunda receiver `resolve_resume_path`-benzeri kontrolü geçer
///     (validate adımları: file_name + total_size + TTL + size match).
#[test]
fn bundle_resume_metadata_dest_path_persisted() {
    let _home = TempHome::new();
    let downloads = tempdir().unwrap();
    let auth_key = [0x99u8; 32];
    let session_id = session_id_i64(&auth_key);
    let session_hex = format!("{:016x}", session_id as u64);
    let bundle_path = downloads
        .path()
        .join(format!(".hekadrop-temp-{session_hex}.bundle"));

    // Simulated partial bundle (yarım yazılmış).
    let partial_bytes: Vec<u8> = (0u8..200).collect();
    fs::write(&bundle_path, &partial_bytes).unwrap();

    let dir = partial_dir().unwrap();
    let now = Utc::now();
    let meta = PartialMeta {
        version: 1,
        session_id_hex: session_hex.clone(),
        payload_id: 5005,
        file_name: "myfolder.bundle".to_string(),
        total_size: 1_000_000,
        received_bytes: partial_bytes.len() as i64,
        chunk_size: CHUNK_SIZE,
        chunk_hmac_chain_b64: "AAEC".to_string(),
        peer_endpoint_id: "peer-Z".to_string(),
        created_at: now,
        updated_at: now,
        dest_path: bundle_path.to_string_lossy().into_owned(),
    };
    meta.store_atomic(&dir).unwrap();

    // Round-trip load.
    let loaded = PartialMeta::load(&dir, session_id, 5005)
        .expect("load")
        .expect("Some");
    assert_eq!(loaded.dest_path, bundle_path.to_string_lossy());
    assert_eq!(loaded.received_bytes, partial_bytes.len() as i64);
    assert_eq!(loaded.payload_id, 5005);

    // Receiver MUST validate (resolve_resume_path replikası):
    let path_from_meta = std::path::PathBuf::from(&loaded.dest_path);
    let md = fs::metadata(&path_from_meta).expect("dest var");
    assert!(md.is_file());
    assert_eq!(
        md.len(),
        loaded.received_bytes as u64,
        "disk size == meta.received_bytes (resolve_resume_path size invariant)"
    );
    let age_days = (Utc::now() - loaded.updated_at).num_days();
    assert!(age_days <= resume::RESUME_TTL_DAYS, "TTL içinde");
    // Bundle path ile string-eşit (connection.rs::handle_sharing_frame'de
    // `resume_eligible` check yolu).
    assert_eq!(path_from_meta, bundle_path);

    // Cleanup.
    let meta_path = dir.join(meta_filename(session_id, 5005));
    let _ = fs::remove_file(&meta_path);
    let _ = fs::remove_file(&bundle_path);
}
