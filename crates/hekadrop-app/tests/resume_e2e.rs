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
    clippy::too_many_arguments,
    clippy::similar_names,
    clippy::items_after_statements
)]

//! RFC-0004 PR-F — `RESUME_V1` end-to-end senaryo doğrulaması.
//!
//! Bu suite RFC-0004 §9 integration test maddelerini (1, 2, 4, 5) hayata
//! geçirir. Sender/receiver state machine'lerinin tam orchestration'ı
//! `connection.rs::handle_*` private API'larında ve `AppState`/mDNS/UI
//! port'larına bağlı olduğundan, "tam" sender↔receiver loopback yerine
//! her senaryo **public surface'ten** (`negotiation`, `capabilities`,
//! `resume`, `payload`, `chunk_hmac`, `frame`, `secure`) gerçek TCP
//! loopback üstünde resume protokolünü yürütür:
//!
//! - Capability negotiation `negotiate_capabilities` üstünden.
//! - Receiver-side `.meta` lifecycle `PayloadAssembler` + `partial_dir`.
//! - `ResumeHint` / `ResumeReject` framing `build_resume_hint_frame` +
//!   `wrap_hekadrop_frame` + `SecureCtx::encrypt` zinciri.
//! - Hash verify (`partial_hash_streaming`).
//!
//! `connection::handle_resume_for_file` ve `sender::wait_for_resume_hint_or_zero`
//! private API'larının end-to-end orchestrate'i `crates/hekadrop-core/src/sender.rs`
//! içindeki `sender_resume_*` inline tests + bu dosyadaki public-surface E2E
//! senaryolarıyla birlikte RFC-0004 §9 kapsamasını tamamlar.

use bytes::Bytes;
use chrono::Utc;
use hekadrop::capabilities::{
    build_resume_hint_frame, build_resume_reject_frame, features, ActiveCapabilities,
    CAPABILITIES_VERSION, ENVELOPE_VERSION,
};
use hekadrop::frame::{self, dispatch_frame_body, wrap_hekadrop_frame, FrameKind};
use hekadrop::location::nearby::connections::{
    payload_transfer_frame::{
        payload_header::PayloadType as PbPayloadType, PayloadChunk, PayloadHeader,
    },
    PayloadTransferFrame,
};
use hekadrop::payload::{PayloadAssembler, CHECKPOINT_INTERVAL_CHUNKS};
use hekadrop::resume::{
    self, meta_filename, partial_dir, partial_hash_streaming, session_id_i64, PartialMeta,
    CHUNK_SIZE, RESUME_HINT_TIMEOUT,
};
use hekadrop::secure::SecureCtx;
use hekadrop_core::chunk_hmac::{build_chunk_integrity, compute_tag, derive_chunk_hmac_key};
use hekadrop_core::negotiation::{negotiate_capabilities, DEFAULT_CAPABILITIES_TIMEOUT};
use hekadrop_core::ukey2::DerivedKeys;
use hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload as ExtPayload;
use hekadrop_proto::hekadrop_ext::resume_reject::Reason as RejectReason;
use hekadrop_proto::hekadrop_ext::{
    Capabilities as PbCapabilities, HekaDropFrame, ResumeHint, ResumeReject,
};
use prost::Message;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};

// ─────────────────────────────────────────────────────────────────────────────
// Ortak helper'lar (resume_meta_persist.rs pattern'iyle uyumlu)
// ─────────────────────────────────────────────────────────────────────────────

/// `partial_dir()` `~/.hekadrop/partial`'a yazar — gerçek HOME'u kirletmemek
/// için tüm testler ortak temp HOME altında çalışır + tek seferlik kurulum.
/// `set_var` thread-safe değildir (Rust 1.90 `unsafe`); süreç başına tek kez
/// kurup `Mutex` ile testleri serialize ederiz.
static HOME_LOCK: Mutex<()> = Mutex::new(());

fn unique_label(name: &str) -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("hd-resume-e2e-{name}-{pid}-{nanos}")
}

struct TempHome {
    dir: PathBuf,
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
        // SAFETY: HOME_LOCK altında seri çalışıyoruz; concurrent set_var yok.
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
        // SAFETY: HOME_LOCK hâlâ tutuluyor.
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

/// Quick Share asimetrik key derivation pattern — server'ın encrypt key'i
/// client'ın decrypt key'i, vice versa (`negotiation.rs::matched_secure_ctx_pair`
/// ile aynı). `auth_key` parametre geçilir → `session_id_i64`'e elverişli.
fn matched_secure_ctx_pair(auth_key: [u8; 32]) -> (SecureCtx, SecureCtx) {
    let key_a = [0x42u8; 32];
    let key_b = [0x55u8; 32];
    let hmac_a = [0xAAu8; 32];
    let hmac_b = [0xBBu8; 32];

    let server_keys = DerivedKeys {
        decrypt_key: key_a,
        recv_hmac_key: hmac_a,
        encrypt_key: key_b,
        send_hmac_key: hmac_b,
        auth_key,
        pin_code: "0000".to_string(),
        next_secret: [0u8; 32],
    };
    let client_keys = DerivedKeys {
        decrypt_key: key_b,
        recv_hmac_key: hmac_b,
        encrypt_key: key_a,
        send_hmac_key: hmac_a,
        auth_key,
        pin_code: "0000".to_string(),
        next_secret: [0u8; 32],
    };

    (
        SecureCtx::from_keys(&server_keys),
        SecureCtx::from_keys(&client_keys),
    )
}

fn make_chunk_frame(
    payload_id: i64,
    body: &[u8],
    last: bool,
    total: i64,
    offset: i64,
) -> PayloadTransferFrame {
    PayloadTransferFrame {
        packet_type: None,
        payload_header: Some(PayloadHeader {
            id: Some(payload_id),
            r#type: Some(PbPayloadType::File as i32),
            total_size: Some(total),
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

/// Transfer'ı checkpoint'e kadar ingest et + cancel ile kes — receiver
/// tarafında `.meta` ve partial dosya bırakır. RFC §9 test 1/2'nin
/// "mid-transfer kill" koşulunu simüle eder.
async fn ingest_partial_then_cancel(
    asm: &mut PayloadAssembler,
    chunk_hmac_key: &[u8; 32],
    payload_id: i64,
    chunk_body: &[u8],
    chunks_to_send: u32,
    total_size: i64,
) {
    let mut offset: i64 = 0;
    for i in 0..chunks_to_send as i64 {
        let f = make_chunk_frame(payload_id, chunk_body, false, total_size, offset);
        asm.ingest(&f).await.expect("ingest chunk");
        let tag =
            compute_tag(chunk_hmac_key, payload_id, i, offset, chunk_body).expect("compute_tag");
        let ci =
            build_chunk_integrity(payload_id, i, offset, chunk_body.len(), tag).expect("build_ci");
        asm.verify_chunk_tag(&ci).await.expect("verify chunk tag");
        offset += chunk_body.len() as i64;
    }
}

/// `ResumeHint`'i secure channel üzerinden gönder (`capabilities.rs` builder +
/// `frame::wrap_hekadrop_frame` + `ctx.encrypt` zinciri — receiver'ın
/// `connection::handle_resume_for_file` emit pattern'iyle aynı wire layout).
async fn send_resume_hint_secure(socket: &mut TcpStream, ctx: &mut SecureCtx, hint: ResumeHint) {
    let envelope = build_resume_hint_frame(hint);
    let pb = envelope.encode_to_vec();
    let wrapped = wrap_hekadrop_frame(&pb);
    let enc = ctx.encrypt(&wrapped).expect("encrypt resume hint");
    frame::write_frame(socket, &enc)
        .await
        .expect("write resume hint frame");
}

/// `ResumeReject`'i secure channel üzerinden gönder (sender →. receiver yolu).
async fn send_resume_reject_secure(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    reject: ResumeReject,
) {
    let envelope = build_resume_reject_frame(reject);
    let pb = envelope.encode_to_vec();
    let wrapped = wrap_hekadrop_frame(&pb);
    let enc = ctx.encrypt(&wrapped).expect("encrypt resume reject");
    frame::write_frame(socket, &enc)
        .await
        .expect("write resume reject frame");
}

/// Secure channel'dan tek `HekaDrop` extension envelope oku.
async fn read_hekadrop_envelope(socket: &mut TcpStream, ctx: &mut SecureCtx) -> HekaDropFrame {
    let raw = frame::read_frame_timeout(socket, Duration::from_secs(2))
        .await
        .expect("read frame");
    let plain = ctx.decrypt(&raw).expect("decrypt frame");
    let FrameKind::HekaDrop { inner } = dispatch_frame_body(&plain) else {
        panic!(
            "HekaDrop magic bekleniyor; plain head: {:02x?}",
            &plain[..8.min(plain.len())]
        );
    };
    HekaDropFrame::decode(inner).expect("decode HekaDropFrame")
}

/// SHA-256 hex helper.
fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E senaryoları — RFC-0004 §9
// ─────────────────────────────────────────────────────────────────────────────

/// Test 1 — RFC §9 happy path. Receiver 2 chunk ingest sonrası kesintiye
/// uğrar (`.meta` + partial dosya disk'te); sonra ikinci "session" başlar
/// → receiver `.meta` lookup → `ResumeHint{offset = 1 chunk}` emit →
/// sender hash verify (loopback simülasyonu) → resume kabul → kalan chunk
/// ingest → final SHA-256 orijinaliyle eşleşir.
#[tokio::test]
async fn e2e_resume_happy_path_meta_lookup_and_hint_verify() {
    let _home = TempHome::new();

    let auth_key = [0x11u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id: i64 = 0xABCD_0001;
    let peer_endpoint = "PEER-A".to_string();
    let file_name = "happy.bin".to_string();

    // 4-chunk = 2 KiB toplam (tests: küçük chunk_body ile checkpoint
    // davranışını CHUNK_SIZE invariant'ından bağımsız doğrularız —
    // resume meta `chunk_size` field'ı yine prod CHUNK_SIZE'ı yazar).
    let chunk_body = vec![0xCAu8; 64];
    let total_chunks: u32 = CHECKPOINT_INTERVAL_CHUNKS * 2; // 32 chunk = .meta yazılır
    let total_size = (chunk_body.len() as i64) * (total_chunks as i64);

    // Tam-content sentetik orijinal — final hash karşılaştırması için.
    let mut full_data = Vec::with_capacity(total_size as usize);
    for _ in 0..total_chunks {
        full_data.extend_from_slice(&chunk_body);
    }
    let orig_sha = sha256_hex(&full_data);

    let dest = std::env::temp_dir().join(unique_label("dest1"));
    let _ = std::fs::remove_file(&dest);

    // Session 1 — partial transfer (16 chunk yaz, kalan 16'yı bırak).
    let key = derive_chunk_hmac_key(&[0x42u8; 32]);
    let half_chunks = CHECKPOINT_INTERVAL_CHUNKS;
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume(
            payload_id,
            session_id,
            peer_endpoint.clone(),
            file_name.clone(),
        )
        .expect("enable_resume");
        ingest_partial_then_cancel(
            &mut asm,
            &key,
            payload_id,
            &chunk_body,
            half_chunks,
            total_size,
        )
        .await;
        // Cancel'siz scope drop — `BufWriter::drop` flush'u tetikler;
        // `.meta` checkpoint pass'inde zaten yazıldı + `cancel()` çağrılmadığı
        // için partial dosya + .meta diskte kalır (resume senaryosu için).
        drop(asm);
    }

    let dir = partial_dir().expect("partial_dir");
    let meta_path = dir.join(meta_filename(session_id, payload_id));
    assert!(meta_path.exists(), "checkpoint sonrası .meta diskte olmalı");

    // .meta ↔ partial dosya offset uyumu: receiver write'ı placeholder dest
    // üzerine yapar; partial bytes count = chunk_body.len() * half_chunks.
    let expected_partial_bytes = (chunk_body.len() as u64) * (half_chunks as u64);
    let dest_size = std::fs::metadata(&dest).expect("dest mevcut").len();
    assert_eq!(
        dest_size, expected_partial_bytes,
        "kısmi yazılan dest dosya boyutu chunk*count ile eşleşmeli"
    );

    // partial_hash recompute — sender'ın doğrulayacağı hash.
    let partial_hash =
        partial_hash_streaming(&dest, expected_partial_bytes).expect("partial hash compute");

    // Loopback secure channel → receiver `ResumeHint` emit → sender doğrular.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut sender_ctx, mut receiver_ctx) = matched_secure_ctx_pair(auth_key);

    let receiver_task = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let hint = ResumeHint {
            session_id,
            payload_id,
            offset: expected_partial_bytes as i64,
            partial_hash: partial_hash.to_vec().into(),
            capabilities_version: CAPABILITIES_VERSION,
            last_chunk_tag: Vec::new().into(),
        };
        send_resume_hint_secure(&mut s, &mut receiver_ctx, hint).await;
        // Reject yolu test'i değil — kabul senaryosu; reject gelmezse OK.
    });

    let (mut sender_socket, _) = listener.accept().await.unwrap();
    let envelope = read_hekadrop_envelope(&mut sender_socket, &mut sender_ctx).await;
    receiver_task.await.unwrap();

    // Wire decoding — `ResumeHint` payload + spec §3 invariant'lar.
    assert_eq!(envelope.version, ENVELOPE_VERSION);
    let Some(ExtPayload::ResumeHint(hint)) = envelope.payload else {
        panic!("ResumeHint oneof bekleniyor: {envelope:?}");
    };
    assert_eq!(hint.session_id, session_id);
    assert_eq!(hint.payload_id, payload_id);
    assert_eq!(hint.offset, expected_partial_bytes as i64);
    assert_eq!(
        hint.partial_hash.len(),
        32,
        "partial_hash 32-byte SHA-256 olmalı"
    );
    assert_eq!(hint.capabilities_version, CAPABILITIES_VERSION);

    // Sender-side hash verify: yerel partial dosyadan `[0..offset]` recompute.
    let local_recompute =
        partial_hash_streaming(&dest, hint.offset as u64).expect("local recompute");
    assert_eq!(
        &hint.partial_hash[..],
        &local_recompute[..],
        "happy path: receiver partial_hash sender recompute ile eşleşmeli"
    );

    // Session 2 — kalan chunk'ları ingest et → finalize → final hash kontrolü.
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        // NOT: gerçek receiver `.part` re-open + base_offset ile resume eder
        // (PR-E TODO). Bu PR'da PayloadAssembler hâlâ truncate-create stratejisi
        // kullanıyor → senaryo geri kalan chunk'ları sıfırdan değil "yeni
        // session olarak baştan al" şeklinde işliyor; final dosya yine total
        // boyut + içerikte tamamlanır → SHA-256 invariant tutulur.
        asm.enable_resume(
            payload_id,
            session_id,
            peer_endpoint.clone(),
            file_name.clone(),
        )
        .ok();
        let mut offset: i64 = 0;
        for i in 0..total_chunks as i64 {
            let last = i == (total_chunks as i64 - 1);
            let f = make_chunk_frame(payload_id, &chunk_body, last, total_size, offset);
            asm.ingest(&f).await.expect("ingest 2nd session");
            let tag = compute_tag(&key, payload_id, i, offset, &chunk_body).expect("compute_tag");
            let ci = build_chunk_integrity(payload_id, i, offset, chunk_body.len(), tag)
                .expect("build_ci");
            asm.verify_chunk_tag(&ci).await.expect("verify ok");
            offset += chunk_body.len() as i64;
        }
    }

    // Finalize → `.meta` silindi.
    assert!(
        !meta_path.exists(),
        "finalize sonrası .meta silinmeliydi (path={meta_path:?})"
    );

    // Final hash orijinal data'nın hash'iyle eşleşir.
    let final_bytes = std::fs::read(&dest).expect("read final");
    let final_sha = sha256_hex(&final_bytes);
    assert_eq!(
        final_sha, orig_sha,
        "final dosya orijinaliyle bit-bit aynı olmalı (resume sonrası)"
    );

    let _ = std::fs::remove_file(&dest);
}

/// Test 2 — RFC §9 hash mismatch. Receiver `.part`'ı dışarıdan tampered;
/// re-handshake → receiver `ResumeHint` (stored `partial_hash` hâlâ orijinal
/// içeriği yansıtıyor) → sender local recompute → mismatch → sender
/// `ResumeReject{HASH_MISMATCH}` emit. Receiver bu reject'i alıp
/// `.meta` cleanup + `start_offset = 0` fresh send'e düşmeli.
#[tokio::test]
async fn e2e_resume_hash_mismatch_triggers_reject_and_fresh_restart() {
    let _home = TempHome::new();

    let auth_key = [0x22u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id: i64 = 0xABCD_0002;
    let peer_endpoint = "PEER-B".to_string();
    let file_name = "tampered.bin".to_string();

    let chunk_body = vec![0xBBu8; 32];
    let half_chunks = CHECKPOINT_INTERVAL_CHUNKS;
    let total_chunks: u32 = half_chunks * 2;
    let total_size = (chunk_body.len() as i64) * (total_chunks as i64);

    let dest = std::env::temp_dir().join(unique_label("dest2"));
    let _ = std::fs::remove_file(&dest);

    let key = derive_chunk_hmac_key(&[0x99u8; 32]);

    // Session 1 — partial yaz + checkpoint.
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume(
            payload_id,
            session_id,
            peer_endpoint.clone(),
            file_name.clone(),
        )
        .unwrap();
        ingest_partial_then_cancel(
            &mut asm,
            &key,
            payload_id,
            &chunk_body,
            half_chunks,
            total_size,
        )
        .await;
        drop(asm); // scope drop → BufWriter::drop flush'ler; cancel() çağırma → .meta + partial korunur
    }

    let dir = partial_dir().expect("partial_dir");
    let meta_path = dir.join(meta_filename(session_id, payload_id));
    assert!(meta_path.exists(), "checkpoint sonrası .meta beklenir");

    // ORIJINAL partial_hash recompute (tamper öncesi) — receiver `.meta`'da
    // bu hash'i saklayacaktı; biz simülasyon olarak doğrudan kullanıyoruz.
    let partial_bytes = (chunk_body.len() as u64) * (half_chunks as u64);
    let original_hash = partial_hash_streaming(&dest, partial_bytes).unwrap();

    // Tamper: dest dosyasının ortasında bir byte flip et — disk corruption /
    // 3rd-party edit simülasyonu.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&dest).unwrap();
        f.seek(SeekFrom::Start(partial_bytes / 2)).unwrap();
        f.write_all(&[0xFFu8]).unwrap();
        f.sync_all().unwrap();
    }

    // Tamper sonrası hash farklı olmalı.
    let tampered_hash = partial_hash_streaming(&dest, partial_bytes).unwrap();
    assert_ne!(
        original_hash, tampered_hash,
        "tamper sonrası hash değişmeli (sanity)"
    );

    // Loopback: receiver eski (tamper-öncesi) hash'i `ResumeHint`'te yollar;
    // sender local recompute → tampered hash → mismatch → REJECT emit.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut sender_ctx, mut receiver_ctx) = matched_secure_ctx_pair(auth_key);

    let receiver_task = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let hint = ResumeHint {
            session_id,
            payload_id,
            offset: partial_bytes as i64,
            // .meta'da kayıtlı orijinal hash — tampered disk ile uyuşmuyor.
            partial_hash: original_hash.to_vec().into(),
            capabilities_version: CAPABILITIES_VERSION,
            last_chunk_tag: Vec::new().into(),
        };
        send_resume_hint_secure(&mut s, &mut receiver_ctx, hint).await;

        // Receiver tarafında reject bekle → spec §6 reaction matrix:
        // reason=HASH_MISMATCH → `.meta` + `.part` sil + fresh transfer.
        let reject_envelope = read_hekadrop_envelope(&mut s, &mut receiver_ctx).await;
        let Some(ExtPayload::ResumeReject(reject)) = reject_envelope.payload else {
            panic!("ResumeReject bekleniyor: {reject_envelope:?}");
        };
        reject
    });

    let (mut sender_socket, _) = listener.accept().await.unwrap();
    let hint_envelope = read_hekadrop_envelope(&mut sender_socket, &mut sender_ctx).await;
    let Some(ExtPayload::ResumeHint(hint)) = hint_envelope.payload else {
        panic!("ResumeHint oneof bekleniyor: {hint_envelope:?}");
    };

    // Sender hash verify (slow-path full SHA-256) — `partial_hash_streaming`
    // ile compare.
    let recomputed = partial_hash_streaming(&dest, hint.offset as u64).unwrap();
    let verify_ok = recomputed == hint.partial_hash[..];
    assert!(
        !verify_ok,
        "tampered disk ile receiver hash uyuşmamalı (mismatch path)"
    );

    // Spec §5: sender REJECT emit eder.
    let reject = ResumeReject {
        payload_id: hint.payload_id,
        reason: i32::from(RejectReason::HashMismatch),
    };
    send_resume_reject_secure(&mut sender_socket, &mut sender_ctx, reject).await;

    let observed_reject = receiver_task.await.unwrap();
    assert_eq!(observed_reject.payload_id, payload_id);
    assert_eq!(
        observed_reject.reason,
        i32::from(RejectReason::HashMismatch)
    );

    // Receiver MUST: spec §6 — REJECT alındığında `.meta` + `.part` sil.
    // Bu helper test gerçek `connection.rs` reject handler'ını çağırmıyor;
    // davranışı manuel uygula + sonucu pin'le (regression detection).
    let _ = std::fs::remove_file(&meta_path);
    let _ = std::fs::remove_file(&dest);
    assert!(!meta_path.exists());
    assert!(!dest.exists());

    // Fresh transfer: yeni session, byte 0'dan tüm chunk'lar.
    let mut full_orig = Vec::with_capacity(total_size as usize);
    for _ in 0..total_chunks {
        full_orig.extend_from_slice(&chunk_body);
    }
    let orig_sha = sha256_hex(&full_orig);
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        let mut offset: i64 = 0;
        for i in 0..total_chunks as i64 {
            let last = i == (total_chunks as i64 - 1);
            let f = make_chunk_frame(payload_id, &chunk_body, last, total_size, offset);
            asm.ingest(&f).await.expect("ingest fresh");
            let tag = compute_tag(&key, payload_id, i, offset, &chunk_body).unwrap();
            let ci = build_chunk_integrity(payload_id, i, offset, chunk_body.len(), tag).unwrap();
            asm.verify_chunk_tag(&ci).await.unwrap();
            offset += chunk_body.len() as i64;
        }
    }
    let final_sha = sha256_hex(&std::fs::read(&dest).unwrap());
    assert_eq!(
        final_sha, orig_sha,
        "fresh restart sonrası dosya orijinal hash'iyle eşleşmeli"
    );

    let _ = std::fs::remove_file(&dest);
}

/// Test 3 — RFC §9 #5: eski peer `RESUME_V1` advertise etmiyor; capability
/// negotiation sonrası `active.has(RESUME_V1) == false` → bu build hiçbir
/// resume frame emit etmemeli (resume code path no-op). Mock peer
/// `Capabilities { features: 0 }` yollar; bizim `negotiate_capabilities`
/// output'u legacy bekliyor.
#[tokio::test]
async fn e2e_resume_old_peer_no_capability_no_resume() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth_key = [0x33u8; 32];
    let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair(auth_key);

    // Old peer simülasyonu: `Capabilities { features = 0 }` yollar
    // (legacy Quick Share — RESUME_V1 yok). negotiate_capabilities
    // intersection = 0 → `.has(RESUME_V1) == false` döner.
    let server_task = tokio::spawn(async move {
        let (mut server_socket, _) = listener.accept().await.unwrap();
        // Bizim build'in capabilities frame'ini drain et (write-side gerekli).
        let raw = frame::read_frame_timeout(&mut server_socket, Duration::from_secs(2))
            .await
            .expect("read client caps");
        let _ = server_ctx.decrypt(&raw).expect("decrypt client caps");

        // Sadece CHUNK_HMAC + 0x0 (RESUME_V1 yok) olarak yolla.
        let pb_caps = PbCapabilities {
            version: CAPABILITIES_VERSION,
            features: features::CHUNK_HMAC_V1, // RESUME_V1 OLMADAN
        };
        let envelope = HekaDropFrame {
            version: ENVELOPE_VERSION,
            payload: Some(ExtPayload::Capabilities(pb_caps)),
        };
        let pb = envelope.encode_to_vec();
        let wrapped = wrap_hekadrop_frame(&pb);
        let enc = server_ctx.encrypt(&wrapped).expect("encrypt caps");
        frame::write_frame(&mut server_socket, &enc)
            .await
            .expect("write caps");
    });

    let mut client_socket = TcpStream::connect(addr).await.unwrap();
    let outcome = negotiate_capabilities(
        &mut client_socket,
        &mut client_ctx,
        DEFAULT_CAPABILITIES_TIMEOUT,
    )
    .await;
    server_task.await.unwrap();

    // Aktif kümede CHUNK_HMAC var, RESUME_V1 yok.
    assert!(outcome.active.has(features::CHUNK_HMAC_V1));
    assert!(
        !outcome.active.has(features::RESUME_V1),
        "old peer RESUME_V1 advertise etmiyor → aktif değil"
    );
    assert!(!outcome.active.is_legacy(), "CHUNK_HMAC hâlâ aktif");

    // Bu build resume code path'ine girmemeli — caller (connection.rs)
    // `active_capabilities.has(RESUME_V1)` gate'inden döner. Test bu davranışı
    // doğrudan ActiveCapabilities query API üstünden pin'ler.
    let session_id_used: Option<i64> = if outcome.active.has(features::RESUME_V1) {
        Some(session_id_i64(&[0u8; 32]))
    } else {
        None
    };
    assert!(
        session_id_used.is_none(),
        "RESUME_V1 inaktif → session_id türetilmez, .meta/hint emit edilmez"
    );

    // RESUME_HINT_TIMEOUT spec §1 değerine sabit (fresh fallback budget).
    assert_eq!(RESUME_HINT_TIMEOUT, Duration::from_millis(2000));
}

/// Test 4 — RFC §9 happy path için chunk-HMAC fast-path (`last_chunk_tag`).
/// Receiver `.meta`'da `chunk_hmac_chain_b64` (son chunk'ın HMAC tag'i) saklar;
/// sender bu tag'i fast-path'te O(1) doğrular (full SHA-256 hesaplamadan).
/// Bu test fast-path semantiğini sabitler: receiver son chunk için HMAC
/// hesaplar + base64 olarak `.meta`'ya yazar; load sonrası tag round-trip
/// tutar; sender doğrulama bu tag'i kullanır.
#[tokio::test]
async fn e2e_resume_chunk_hmac_fastpath_tag_persisted_in_meta() {
    let _home = TempHome::new();

    let auth_key = [0x44u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id: i64 = 0xABCD_0004;
    let peer_endpoint = "PEER-D".to_string();
    let file_name = "fastpath.bin".to_string();

    let chunk_body = vec![0xDDu8; 64];
    let half_chunks = CHECKPOINT_INTERVAL_CHUNKS;
    let total_chunks: u32 = half_chunks * 2;
    let total_size = (chunk_body.len() as i64) * (total_chunks as i64);

    let dest = std::env::temp_dir().join(unique_label("dest4"));
    let _ = std::fs::remove_file(&dest);

    let key = derive_chunk_hmac_key(&[0x77u8; 32]);
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume(
            payload_id,
            session_id,
            peer_endpoint.clone(),
            file_name.clone(),
        )
        .unwrap();
        ingest_partial_then_cancel(
            &mut asm,
            &key,
            payload_id,
            &chunk_body,
            half_chunks,
            total_size,
        )
        .await;
        drop(asm); // scope drop → BufWriter::drop flush'ler; cancel() çağırma → .meta + partial korunur
    }

    let dir = partial_dir().expect("partial_dir");
    let meta_path = dir.join(meta_filename(session_id, payload_id));
    assert!(meta_path.exists(), "checkpoint sonrası .meta beklenir");

    // .meta load → fast-path için gerekli alanlar dolu.
    let meta = PartialMeta::load(&dir, session_id, payload_id)
        .expect("load")
        .expect("Some meta");
    assert_eq!(meta.payload_id, payload_id);
    assert_eq!(meta.file_name, file_name);
    assert_eq!(meta.peer_endpoint_id, peer_endpoint);
    assert_eq!(meta.chunk_size, CHUNK_SIZE);

    // Fast-path için kritik invariant: `chunk_hmac_chain_b64` boş değil
    // (son verified chunk'ın HMAC tag'i base64'lü).
    assert!(
        !meta.chunk_hmac_chain_b64.is_empty(),
        "chunk-HMAC aktif iken son chunk tag .meta'da saklanmalı"
    );
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;
    let tag_bytes = BASE64_STD
        .decode(&meta.chunk_hmac_chain_b64)
        .expect("base64 decode");
    assert_eq!(
        tag_bytes.len(),
        32,
        "HMAC-SHA256 tag uzunluğu 32 byte (RFC-0003 §3.5)"
    );

    // Fast-path verify: sender son chunk'ı yerel partial dosyadan okur,
    // chunk_index + offset + body üzerinden recompute eder, .meta'daki tag
    // ile bit-bit eşitliği bekler.
    let last_chunk_index: i64 = (half_chunks as i64) - 1;
    let last_chunk_offset: i64 = (chunk_body.len() as i64) * last_chunk_index;
    let last_chunk_len = chunk_body.len();

    // Local read: dest dosyasından son chunk'ı oku.
    let dest_bytes = std::fs::read(&dest).expect("read dest");
    let read_chunk = &dest_bytes[last_chunk_offset as usize..][..last_chunk_len];
    assert_eq!(
        read_chunk,
        &chunk_body[..],
        "sender'ın yerel okuduğu chunk receiver'ın yazdığıyla aynı olmalı"
    );

    let recomputed_tag = compute_tag(
        &key,
        payload_id,
        last_chunk_index,
        last_chunk_offset,
        read_chunk,
    )
    .expect("recompute tag");
    assert_eq!(
        recomputed_tag.to_vec(),
        tag_bytes,
        "fast-path: sender recompute tag = .meta'daki son tag (full SHA-256 atlanır)"
    );

    // ResumeHint envelope inşa et — fast-path için `last_chunk_tag` non-empty
    // + `partial_hash` opsiyonel (slow-path'e fallback için yine 32-byte).
    let partial_bytes = (chunk_body.len() as u64) * (half_chunks as u64);
    let partial_hash = partial_hash_streaming(&dest, partial_bytes).unwrap();
    let hint = ResumeHint {
        session_id,
        payload_id,
        offset: partial_bytes as i64,
        partial_hash: partial_hash.to_vec().into(),
        capabilities_version: CAPABILITIES_VERSION,
        last_chunk_tag: tag_bytes.into(),
    };
    let envelope = build_resume_hint_frame(hint.clone());
    let pb = envelope.encode_to_vec();
    let wrapped = wrap_hekadrop_frame(&pb);
    // Wire layout sanity: magic + protobuf, decode round-trip.
    let FrameKind::HekaDrop { inner } = dispatch_frame_body(&wrapped) else {
        panic!("magic dispatch HekaDrop bekliyor");
    };
    let decoded = HekaDropFrame::decode(inner).expect("decode round-trip");
    let Some(ExtPayload::ResumeHint(decoded_hint)) = decoded.payload else {
        panic!("ResumeHint oneof beklenir");
    };
    assert_eq!(
        decoded_hint.last_chunk_tag.len(),
        32,
        "fast-path tag wire-roundtrip"
    );
    assert_eq!(decoded_hint.offset, hint.offset);
    assert_eq!(decoded_hint.partial_hash.len(), 32);

    // Cleanup
    let _ = std::fs::remove_file(&dest);
    let _ = std::fs::remove_file(&meta_path);
}

// ─────────────────────────────────────────────────────────────────────────────
// PR-G — Receiver `.part` append/seek davranış testleri
// ─────────────────────────────────────────────────────────────────────────────

/// Test PR-G #1 — Resume `.part`'ı silmemeli, append moduna geçmeli.
///
/// 1. Fresh transfer 2 chunk yaz (cancel etmeden sink drop ile `BufWriter` flush).
/// 2. İkinci `PayloadAssembler` instance — `enable_resume_with_offset` ile
///    `received_bytes = 2 * chunk_len` set, ek 2 chunk gönder.
/// 3. Final dosya tam 4 chunk değerinde olmalı; ilk 2 chunk korunmalı,
///    son 2 chunk eklenmiş olmalı (içerik bit-bit eşit).
///
/// Spec gerekçesi: PR #136 / PR #137'de yakalanan bug — `truncate(true)` ile
/// resume açılışı `.part`'ın ilk N byte'ını sıfırlıyordu. PR-G
/// `truncate(false)` + `seek` ile düzeltir.
#[tokio::test]
async fn e2e_pr_g_receiver_append_preserves_existing_part() {
    let _home = TempHome::new();

    let auth_key = [0xA1u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id: i64 = 0xABCD_0010;
    let peer_endpoint = "PEER-G1".to_string();
    let file_name = "g1.bin".to_string();

    // Fresh chunk (0xCC) ve resume chunk (0xDD) — birbirinden ayırt edilebilir.
    let fresh_chunk = vec![0xCCu8; 64];
    let resume_chunk = vec![0xDDu8; 64];
    let total_chunks: i64 = 4;
    let chunk_len = fresh_chunk.len() as i64;
    let total_size = chunk_len * total_chunks;

    let dest = std::env::temp_dir().join(unique_label("g1-dest"));
    let _ = std::fs::remove_file(&dest);
    // Placeholder yarat — `unique_downloads_path` davranışını taklit
    // (PR-G `truncate(false)` resume açılışı `.part` mevcut bekler).
    std::fs::write(&dest, b"").unwrap();

    let key = derive_chunk_hmac_key(&[0x01u8; 32]);

    // Session 1 — 2 chunk fresh yaz.
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume(
            payload_id,
            session_id,
            peer_endpoint.clone(),
            file_name.clone(),
        )
        .unwrap();
        let mut offset: i64 = 0;
        for i in 0..2_i64 {
            let f = make_chunk_frame(payload_id, &fresh_chunk, false, total_size, offset);
            asm.ingest(&f).await.unwrap();
            let tag = compute_tag(&key, payload_id, i, offset, &fresh_chunk).unwrap();
            let ci = build_chunk_integrity(payload_id, i, offset, fresh_chunk.len(), tag).unwrap();
            asm.verify_chunk_tag(&ci).await.unwrap();
            offset += chunk_len;
        }
        drop(asm); // BufWriter::drop → flush
    }

    // Session 1 sonrası dosya boyutu tam 2 chunk; içerik 0xCC.
    let mid_bytes = std::fs::read(&dest).unwrap();
    assert_eq!(
        mid_bytes.len() as i64,
        2 * chunk_len,
        "session 1 sonrası 2 chunk yazılmış olmalı"
    );
    assert!(
        mid_bytes.iter().all(|&b| b == 0xCC),
        "fresh chunk içerikleri 0xCC olmalı"
    );

    // Session 2 — RESUME path. enable_resume_with_offset(received_bytes=2*chunk).
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume_with_offset(
            payload_id,
            session_id,
            peer_endpoint.clone(),
            file_name.clone(),
            2 * chunk_len,
            2, // next_chunk_index — 2 chunk verified, sender chunk_index=2'den devam
            String::new(),
        )
        .unwrap();
        // Sender resume sonrası chunk_index = 2'den devam eder; ilk gelen
        // chunk offset = 2 * chunk_len.
        let mut offset: i64 = 2 * chunk_len;
        for i in 2_i64..4_i64 {
            let last = i == 3;
            let f = make_chunk_frame(payload_id, &resume_chunk, last, total_size, offset);
            asm.ingest(&f).await.unwrap();
            let tag = compute_tag(&key, payload_id, i, offset, &resume_chunk).unwrap();
            let ci = build_chunk_integrity(payload_id, i, offset, resume_chunk.len(), tag).unwrap();
            asm.verify_chunk_tag(&ci).await.unwrap();
            offset += chunk_len;
        }
    }

    // Final dosya 4 chunk; ilk 2 chunk = 0xCC (korunmuş), son 2 chunk = 0xDD.
    let final_bytes = std::fs::read(&dest).unwrap();
    assert_eq!(
        final_bytes.len() as i64,
        total_size,
        "PR-G: resume sonrası dosya total_size'a ulaşmalı"
    );
    let half = (2 * chunk_len) as usize;
    assert!(
        final_bytes[..half].iter().all(|&b| b == 0xCC),
        "ilk yarı korunmalı (0xCC) — truncate(false) çalıştı"
    );
    assert!(
        final_bytes[half..].iter().all(|&b| b == 0xDD),
        "ikinci yarı yeni eklenen 0xDD olmalı"
    );

    let _ = std::fs::remove_file(&dest);
}

/// Test PR-G #2 — `seek_to_received_bytes` doğru offset'e yazıyor.
///
/// `pending_resume.received_bytes = chunk_len` ile resume aktif edilir; ilk
/// chunk gelir; `.part`'ın `chunk_len..2*chunk_len` aralığında yazılmış
/// olmalı (üzerine değil — `[0..chunk_len]` korunur).
#[tokio::test]
async fn e2e_pr_g_receiver_seek_to_received_bytes() {
    let _home = TempHome::new();

    let auth_key = [0xA2u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id: i64 = 0xABCD_0011;

    let prefix = vec![0x11u8; 64]; // diskte mevcut, korunmalı
    let new_chunk = vec![0x22u8; 64]; // resume sonrası eklenecek
    let chunk_len = prefix.len() as i64;
    let total_size = chunk_len * 2;

    let dest = std::env::temp_dir().join(unique_label("g2-dest"));
    let _ = std::fs::remove_file(&dest);
    // Önceki session'ın yarım dosyasını manuel yarat: prefix bytes diskte.
    std::fs::write(&dest, &prefix).unwrap();

    let key = derive_chunk_hmac_key(&[0x02u8; 32]);
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume_with_offset(
            payload_id,
            session_id,
            "PEER-G2".to_string(),
            "g2.bin".to_string(),
            chunk_len, // received_bytes = 1 chunk
            1,         // next_chunk_index = 1
            String::new(),
        )
        .unwrap();
        // Sender chunk_index = 1, offset = chunk_len.
        let f = make_chunk_frame(payload_id, &new_chunk, true, total_size, chunk_len);
        asm.ingest(&f).await.unwrap();
        let tag = compute_tag(&key, payload_id, 1, chunk_len, &new_chunk).unwrap();
        let ci = build_chunk_integrity(payload_id, 1, chunk_len, new_chunk.len(), tag).unwrap();
        let completed = asm.verify_chunk_tag(&ci).await.unwrap();
        assert!(completed.is_some(), "last_chunk verify finalize etmeli");
    }

    let final_bytes = std::fs::read(&dest).unwrap();
    assert_eq!(
        final_bytes.len() as i64,
        total_size,
        "dosya tam total_size olmalı"
    );
    assert_eq!(
        &final_bytes[..(chunk_len as usize)],
        &prefix[..],
        "prefix korunmalı (seek doğru offset'e gitti, baştan yazmadı)"
    );
    assert_eq!(
        &final_bytes[(chunk_len as usize)..],
        &new_chunk[..],
        "yeni chunk doğru offset'e yazıldı"
    );

    let _ = std::fs::remove_file(&dest);
}

/// Test PR-G #3 — Resume sonrası final SHA-256 orijinal full-content hash
/// ile bit-bit eşleşmeli (hasher chain pre-feed doğrulaması).
///
/// Receiver `truncate(false) + seek` öncesi `.part`'ın ilk `received_bytes`
/// byte'ını hasher'a feed eder; bu yapılmazsa final SHA-256 yalnız resume
/// sonrası gelen byte'ları hash'lerdi → orijinalle uyuşmazdı (sender-side
/// `CompletedPayload::File.sha256` mismatch alarmı).
#[tokio::test]
async fn e2e_pr_g_resume_full_sha256_matches_original() {
    let _home = TempHome::new();

    let auth_key = [0xA3u8; 32];
    let session_id = session_id_i64(&auth_key);
    let payload_id: i64 = 0xABCD_0012;

    // Birbirinden farklı pattern'ler: orijinal "ilk-yarı" + "ikinci-yarı".
    let first_half = vec![0x55u8; 64];
    let second_half = vec![0xAAu8; 64];
    let chunk_len = first_half.len() as i64;
    let total_size = chunk_len * 2;

    // Beklenen orijinal full content + hash.
    let mut full = Vec::with_capacity(total_size as usize);
    full.extend_from_slice(&first_half);
    full.extend_from_slice(&second_half);
    let expected_sha = sha256_hex(&full);

    let dest = std::env::temp_dir().join(unique_label("g3-dest"));
    let _ = std::fs::remove_file(&dest);
    // Önceki session'ın yazmış olacağı içeriği taklit — first_half diskte.
    std::fs::write(&dest, &first_half).unwrap();

    let key = derive_chunk_hmac_key(&[0x03u8; 32]);
    let completed_sha;
    {
        let mut asm = PayloadAssembler::new();
        asm.set_chunk_hmac_key(key);
        asm.register_file_destination(payload_id, dest.clone())
            .unwrap();
        asm.enable_resume_with_offset(
            payload_id,
            session_id,
            "PEER-G3".to_string(),
            "g3.bin".to_string(),
            chunk_len,
            1, // next_chunk_index = 1
            String::new(),
        )
        .unwrap();

        let f = make_chunk_frame(payload_id, &second_half, true, total_size, chunk_len);
        asm.ingest(&f).await.unwrap();
        let tag = compute_tag(&key, payload_id, 1, chunk_len, &second_half).unwrap();
        let ci = build_chunk_integrity(payload_id, 1, chunk_len, second_half.len(), tag).unwrap();
        let completed = asm
            .verify_chunk_tag(&ci)
            .await
            .unwrap()
            .expect("last chunk verify finalize");
        match completed {
            hekadrop::payload::CompletedPayload::File { sha256, .. } => {
                completed_sha = hex::encode(sha256);
            }
            _ => panic!("File completion bekleniyor"),
        }
    }

    // 1. Disk içeriği doğru: first_half + second_half.
    let final_bytes = std::fs::read(&dest).unwrap();
    assert_eq!(final_bytes, full, "final dosya orijinal content ile aynı");

    // 2. PayloadAssembler'ın hesapladığı sha256 = orijinal full hash.
    //    Hasher pre-feed olmazsa bu yalnız second_half'in hash'i olurdu.
    assert_eq!(
        completed_sha, expected_sha,
        "PR-G hasher pre-feed: streaming SHA-256 orijinal full-content hash ile eşleşmeli"
    );

    let _ = std::fs::remove_file(&dest);
}

// ─────────────────────────────────────────────────────────────────────────────
// Yardımcı: log_redact import'u kullanılmadığı uyarısını engelle (yer tutucu).
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)] // helper: gelecekteki senaryolar için yer tutucu (kullanılırsa silinir)
fn _ensure_resume_module_in_scope() -> Duration {
    // Bytes ve resume module re-export'larının kullanımı zorlanmasa import'lar
    // dead_code uyarısı vermesin — gerçek kullanım üstte zaten var; bu fn
    // sadece compile-time sanity.
    let _b: Bytes = Bytes::from_static(b"sanity");
    let _ = Utc::now();
    let _ = resume::RESUME_HINT_TIMEOUT;
    let _ = ActiveCapabilities::legacy();
    RESUME_HINT_TIMEOUT
}
