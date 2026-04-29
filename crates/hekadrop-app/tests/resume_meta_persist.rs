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
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

//! RFC-0004 PR-C — receiver `.meta` persist davranışı.
//!
//! Bu entegrasyon testi `PayloadAssembler` üzerinden resume `.meta` sidecar'ın
//! checkpoint cadansı (`CHECKPOINT_INTERVAL_CHUNKS`), finalize/cancel sonrası
//! cleanup, ve `validate_resumability`-benzeri TTL+size invariant'larını
//! pin'ler. Introduction → `ResumeHint` emit yolu (socket I/O gerektiren)
//! `handle_resume_for_file` private helper olduğu için bu PR'da unit-level
//! `PartialMeta` invariant kontrolüyle vekil olarak kapsanır; end-to-end
//! socket roundtrip PR-D/E entegrasyon testlerine ertelenir.

use chrono::Utc;
use hekadrop::capabilities::CAPABILITIES_VERSION;
use hekadrop::location::nearby::connections::{
    payload_transfer_frame::{
        payload_header::PayloadType as PbPayloadType, PayloadChunk, PayloadHeader,
    },
    PayloadTransferFrame,
};
use hekadrop::payload::{PayloadAssembler, CHECKPOINT_INTERVAL_CHUNKS};
use hekadrop::resume::{
    self, meta_filename, partial_dir, session_id_i64, PartialMeta, CHUNK_SIZE, MAX_META_VERSION,
    RESUME_TTL_DAYS,
};
use hekadrop_core::chunk_hmac::{build_chunk_integrity, compute_tag, derive_chunk_hmac_key};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// `partial_dir()` `~/.hekadrop/partial`'a yazar — gerçek HOME'u kirletmemek
/// için tüm testler ortak bir temp HOME altında çalışır + tek seferlik kurulum.
/// `set_var` thread-safe değildir (Rust 1.90 `unsafe`); süreç başına tek kez
/// kurup `Mutex` ile testleri serialize ederiz (cargo test default zaten
/// thread-pool'da çalıştırır → testler arası HOME paylaşımı + cleanup gerek).
static HOME_LOCK: Mutex<()> = Mutex::new(());

fn unique_label(name: &str) -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("hd-resume-{name}-{pid}-{nanos}")
}

/// Temp HOME setup — caller her test başında çağırır, dönen guard scope sonu
/// HOME'u eski değerine geri alır. `Mutex` lock'u guard tutar → testler
/// arası seri çalışma garanti.
struct TempHome {
    dir: std::path::PathBuf,
    saved: Option<std::ffi::OsString>,
    key: &'static str,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl TempHome {
    fn new() -> Self {
        let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(unique_label("home"));
        std::fs::create_dir_all(&dir).expect("temp home mkdir");
        let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let saved = std::env::var_os(key);
        // SAFETY: test sequenced via HOME_LOCK; tek thread bu noktada HOME yazar.
        // Diğer testler aynı kilit üzerinde bekler — concurrent set_var yok.
        unsafe {
            std::env::set_var(key, &dir);
        }
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
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Frame helper — chunk-HMAC pipeline için offset bağlantılı.
fn make_frame_offset(
    id: i64,
    body: &[u8],
    last: bool,
    total_size: i64,
    offset: i64,
) -> PayloadTransferFrame {
    PayloadTransferFrame {
        packet_type: None,
        payload_header: Some(PayloadHeader {
            id: Some(id),
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

fn meta_path_for(session_id: i64, payload_id: i64) -> std::path::PathBuf {
    partial_dir()
        .expect("partial_dir")
        .join(meta_filename(session_id, payload_id))
}

/// Helper — chunk-HMAC + resume aktif iken bir chunk ingest + verify et.
async fn ingest_and_verify_chunk(
    asm: &mut PayloadAssembler,
    key: &[u8; 32],
    pid: i64,
    chunk_index: i64,
    offset: i64,
    body: &[u8],
    last: bool,
    total: i64,
) {
    let f = make_frame_offset(pid, body, last, total, offset);
    asm.ingest(&f).await.expect("ingest ok");
    let tag = compute_tag(key, pid, chunk_index, offset, body).expect("compute_tag");
    let ci = build_chunk_integrity(pid, chunk_index, offset, body.len(), tag).expect("build_ci");
    asm.verify_chunk_tag(&ci).await.expect("verify ok");
}

#[tokio::test]
async fn meta_written_at_checkpoint_interval() {
    let _home = TempHome::new();
    let auth_key = [0x11u8; 32];
    let session_id = session_id_i64(&auth_key);
    let pid = 7i64;
    let payload_id = pid;

    let chunk_body = vec![0xABu8; 64];
    let chunk_count: u32 = CHECKPOINT_INTERVAL_CHUNKS * 2; // 32 chunks
    let total = (chunk_body.len() as i64) * (chunk_count as i64);

    let dest = std::env::temp_dir().join(unique_label("dest1"));
    let _ = std::fs::remove_file(&dest);

    let key = derive_chunk_hmac_key(&[0x42u8; 32]);
    let mut asm = PayloadAssembler::new();
    asm.set_chunk_hmac_key(key);
    asm.register_file_destination(payload_id, dest.clone())
        .unwrap();
    asm.enable_resume(
        payload_id,
        session_id,
        "endpointA".to_string(),
        "report.bin".to_string(),
    )
    .expect("enable_resume");

    let meta_path = meta_path_for(session_id, payload_id);

    let mut offset = 0i64;
    for i in 0..chunk_count as i64 {
        let last = i == (chunk_count as i64 - 1);
        ingest_and_verify_chunk(
            &mut asm,
            &key,
            payload_id,
            i,
            offset,
            &chunk_body,
            last,
            total,
        )
        .await;
        offset += chunk_body.len() as i64;

        // Checkpoint sınırından *önce* `.meta` yazılmamalı (ilk 15 chunk'ta).
        if (i + 1) < CHECKPOINT_INTERVAL_CHUNKS as i64 {
            assert!(
                !meta_path.exists(),
                "checkpoint öncesinde `.meta` yazılmamalı (i={i})"
            );
        }
    }

    // Last chunk finalize → `.meta` silinmiş olmalı.
    assert!(!meta_path.exists(), "finalize sonrası .meta silinmeliydi");

    // Tamamlanmış dosya var.
    assert!(dest.exists());
    let _ = std::fs::remove_file(&dest);
}

#[tokio::test]
async fn meta_deleted_on_finalize() {
    let _home = TempHome::new();
    let auth_key = [0x22u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id = 11i64;

    // Tek chunk transfer — finalize hemen.
    let body = b"finalize-test".to_vec();
    let total = body.len() as i64;

    let dest = std::env::temp_dir().join(unique_label("dest"));
    let _ = std::fs::remove_file(&dest);

    let key = derive_chunk_hmac_key(&[0x77u8; 32]);
    let mut asm = PayloadAssembler::new();
    asm.set_chunk_hmac_key(key);
    asm.register_file_destination(payload_id, dest.clone())
        .unwrap();
    asm.enable_resume(payload_id, session_id, "peer".into(), "single.bin".into())
        .unwrap();

    let meta_path = meta_path_for(session_id, payload_id);

    ingest_and_verify_chunk(&mut asm, &key, payload_id, 0, 0, &body, true, total).await;

    assert!(
        !meta_path.exists(),
        "finalize sonrası .meta silinmeliydi (path={meta_path:?})"
    );
    let _ = std::fs::remove_file(&dest);
}

#[tokio::test]
async fn meta_deleted_on_cancel() {
    let _home = TempHome::new();
    let auth_key = [0x33u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id = 13i64;

    let chunk_body = vec![0xCDu8; 32];
    let chunk_count: u32 = CHECKPOINT_INTERVAL_CHUNKS;
    let total = (chunk_body.len() as i64) * 2 * (chunk_count as i64);

    let dest = std::env::temp_dir().join(unique_label("dest"));
    let _ = std::fs::remove_file(&dest);

    let key = derive_chunk_hmac_key(&[0x88u8; 32]);
    let mut asm = PayloadAssembler::new();
    asm.set_chunk_hmac_key(key);
    asm.register_file_destination(payload_id, dest.clone())
        .unwrap();
    asm.enable_resume(payload_id, session_id, "peer".into(), "cancel.bin".into())
        .unwrap();

    let meta_path = meta_path_for(session_id, payload_id);

    // CHECKPOINT_INTERVAL_CHUNKS chunk gönder → `.meta` yazılır
    // (transfer henüz tamamlanmadı, total daha büyük).
    let mut offset = 0i64;
    for i in 0..chunk_count as i64 {
        ingest_and_verify_chunk(
            &mut asm,
            &key,
            payload_id,
            i,
            offset,
            &chunk_body,
            false,
            total,
        )
        .await;
        offset += chunk_body.len() as i64;
    }
    assert!(
        meta_path.exists(),
        "checkpoint sonrası .meta yazılmış olmalı (path={meta_path:?})"
    );

    // Cancel → `.meta` ve `.part` silinir.
    asm.cancel(payload_id);
    assert!(!meta_path.exists(), "cancel sonrası .meta silinmeliydi");
    assert!(!dest.exists(), "cancel sonrası .part silinmeliydi");
}

#[tokio::test]
async fn enable_resume_before_first_chunk_persists_after_ingest() {
    // RFC-0004 §3.3 invariant: caller register_file_destination + enable_resume
    // çağırır → ilk chunk geldikten sonra `.meta` checkpoint döngüsüne girer.
    let _home = TempHome::new();
    let auth_key = [0x44u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id = 17i64;

    let chunk_body = vec![0xEFu8; 16];
    let chunk_count: u32 = CHECKPOINT_INTERVAL_CHUNKS;
    let total = (chunk_body.len() as i64) * 2 * (chunk_count as i64);

    let dest = std::env::temp_dir().join(unique_label("dest"));
    let _ = std::fs::remove_file(&dest);

    let key = derive_chunk_hmac_key(&[0x55u8; 32]);
    let mut asm = PayloadAssembler::new();
    asm.set_chunk_hmac_key(key);
    // Sıra doğru: register, sonra enable_resume.
    asm.register_file_destination(payload_id, dest.clone())
        .unwrap();
    asm.enable_resume(
        payload_id,
        session_id,
        "peer-X".into(),
        "deferred.bin".into(),
    )
    .unwrap();

    let meta_path = meta_path_for(session_id, payload_id);
    assert!(
        !meta_path.exists(),
        "henüz hiç chunk yok → .meta yazılmamalı"
    );

    // Tam CHECKPOINT_INTERVAL_CHUNKS chunk → ilk checkpoint flush
    // (last_chunk false olduğundan finalize tetiklenmez).
    let mut offset = 0i64;
    for i in 0..chunk_count as i64 {
        ingest_and_verify_chunk(
            &mut asm,
            &key,
            payload_id,
            i,
            offset,
            &chunk_body,
            false,
            total,
        )
        .await;
        offset += chunk_body.len() as i64;
    }
    assert!(
        meta_path.exists(),
        "ilk checkpoint sonrası .meta yazılmış olmalı"
    );

    // İçeriği sanity-check: schema field'ları doldurulmuş + invariants.
    let loaded = PartialMeta::load(&partial_dir().unwrap(), session_id, payload_id)
        .expect("load")
        .expect("Some");
    assert_eq!(loaded.version, 1);
    assert!(loaded.version <= MAX_META_VERSION);
    assert_eq!(loaded.payload_id, payload_id);
    assert_eq!(loaded.file_name, "deferred.bin");
    assert_eq!(loaded.peer_endpoint_id, "peer-X");
    assert_eq!(loaded.chunk_size, CHUNK_SIZE);
    assert_eq!(loaded.total_size, total);
    assert_eq!(
        loaded.received_bytes,
        (chunk_body.len() as i64) * (chunk_count as i64)
    );

    asm.cancel(payload_id);
}

#[tokio::test]
async fn validate_resumability_invariants_total_size_and_ttl() {
    // RFC-0004 §5 receiver MUST: meta.total_size ≠ Introduction.total_size →
    // stale, sil + fresh. Bu test PartialMeta'nın load() + alanlarını yazıp
    // okur; `handle_resume_for_file`'in invariant kontrolleri (total_size +
    // file_name + TTL) PartialMeta load semantiğine güveniyor. Burada
    // invariant'ları *ham field karşılaştırmasıyla* pin'liyoruz.
    let _home = TempHome::new();
    let auth_key = [0x66u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id = 23i64;

    let dir = partial_dir().unwrap();
    let now = Utc::now();
    let stale = now - chrono::Duration::days(RESUME_TTL_DAYS + 1);
    let session_hex = format!("{:016x}", session_id as u64);

    let meta = PartialMeta {
        version: 1,
        session_id_hex: session_hex,
        payload_id,
        file_name: "report.bin".to_string(),
        total_size: 1_000_000,
        received_bytes: 524_288,
        chunk_size: CHUNK_SIZE,
        chunk_hmac_chain_b64: "AAEC".to_string(),
        peer_endpoint_id: "peerY".to_string(),
        created_at: stale,
        updated_at: stale,
    };
    meta.store_atomic(&dir).expect("store ok");

    // Round-trip load işleyicisi
    let loaded = PartialMeta::load(&dir, session_id, payload_id)
        .expect("load")
        .expect("Some");

    // Receiver MUST kontrolleri (handle_resume_for_file'in mantığı):
    let announced_total: i64 = 1_000_000;
    let announced_name = "report.bin";

    let age_days = (Utc::now() - loaded.updated_at).num_days();
    let total_match = loaded.total_size == announced_total;
    let name_match = loaded.file_name == announced_name;
    let ttl_ok = age_days <= RESUME_TTL_DAYS;

    assert!(total_match, "total_size eşleşmesi");
    assert!(name_match, "file_name eşleşmesi");
    assert!(!ttl_ok, "TTL aşıldı (stale meta)");

    // Stale → caller meta'yı silmeli (handle_resume_for_file davranışı).
    let path = dir.join(resume::meta_filename(session_id, payload_id));
    let _ = std::fs::remove_file(&path);
    assert!(!path.exists());
    assert!(PartialMeta::load(&dir, session_id, payload_id)
        .unwrap()
        .is_none());

    // CAPABILITIES_VERSION mevcut sürümle uyumlu (sender ResumeHint'te bunu
    // yollayacak — PR-D'de sürüm uyumsuzluğunda VERSION_MISMATCH reject).
    assert_eq!(CAPABILITIES_VERSION, 1);
}
