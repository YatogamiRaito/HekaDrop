//! Quick Share gönderici — Mac → Android yönü.
//!
//! Akış:
//!   1) TCP connect
//!   2) `ConnectionRequest` (plain, bizim `endpoint_info`)
//!   3) UKEY2 client handshake → `DerivedKeys` + PIN
//!   4) Plain `ConnectionResponse` değişimi (biz → peer, peer → biz)
//!   5) `SecureCtx` kur — artık tüm trafik şifreli
//!   6) `PairedKeyEncryption` gönder (biz başlatırız)
//!   7) Peer'den `PairedKeyEncryption` al → `PairedKeyResult` gönder
//!   8) Peer'den `PairedKeyResult` al
//!   9) Introduction gönder (dosya metadata'sı ile)
//!  10) Peer'den Response (Accept/Reject) bekle
//!  11) Accept ise: dosya chunk'larını `PayloadTransfer` olarak gönder
//!  12) Disconnection

use crate::config;
use crate::connection;
use crate::discovery_types::DiscoveredDevice;
use crate::error::HekaError;
use crate::frame;
use crate::location::nearby::connections::{
    connection_request_frame::Medium,
    payload_transfer_frame::{
        self as ptf, payload_header::PayloadType, PayloadChunk, PayloadHeader,
    },
    v1_frame, ConnectionRequestFrame, KeepAliveFrame, OfflineFrame, PayloadTransferFrame, V1Frame,
};
use crate::payload::{CompletedPayload, PayloadAssembler};
use crate::secure::SecureCtx;
use crate::sharing::nearby::{
    connection_response_frame::Status as ConsentStatus, file_metadata::Type as FileKind,
    frame::Version as ShVersion, text_metadata::Type as TextKind, v1_frame as sh_v1, FileMetadata,
    Frame as SharingFrame, IntroductionFrame, TextMetadata, V1Frame as ShV1Frame,
};
use crate::state::{self, AppState, ProgressState};
use crate::ukey2;
use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use prost::Message;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Tek chunk'ta gönderilecek maksimum dosya baytı.
/// Quick Share yönergeleri 512 KB civarını öneriyor; 1 MB sınırı zorlar.
const CHUNK_SIZE: usize = 512 * 1024;

/// Son chunk gönderildikten sonra peer'in Disconnection frame'ini (veya
/// EOF'u) beklemek için üst sınır. Android dosyayı diske yazıp doğrulamayı
/// bitirmeden bizim TCP'yi kapatmamamız için gerekli. 10 sn, 1 GB'lık bir
/// dosyanın Android tarafında fsync + doğrulama süresinden rahat geniştir.
const PEER_DISCONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// RFC-0004 §1: receiver Introduction sonrası `ResumeHint` emit etmek için
/// 2 sn süresi var. Sender bu süre içinde frame görmezse `start_offset = 0`
/// legacy fresh transfer'a düşer (silent fallback). Spec normative değer.
const RESUME_HINT_TIMEOUT: Duration = Duration::from_millis(2000);

pub struct SendRequest {
    pub device: DiscoveredDevice,
    pub files: Vec<std::path::PathBuf>,
}

/// Sender davranışını caller'dan inject edilen platform-bağımlı yardımcılar.
///
/// I-1 (CLAUDE.md): core'a taşınınca `crate::platform`, `crate::i18n`,
/// `crate::paths` referansları sızmasın diye sender artık bu callback +
/// önceden çevrilmiş string'lerle çalışır.
pub struct SendCtx {
    /// Çoklu chunk'lı `Receiving` progress'i ve `Completed` özeti için
    /// metin kısa adı (örn. "metin"). Caller `i18n::t("sender.text_summary")`
    /// çağırıp passing eder.
    pub text_summary: String,
}

struct PlannedFile {
    path: std::path::PathBuf,
    name: String,
    size: i64,
    payload_id: i64,
}

pub async fn send(req: SendRequest, state: Arc<AppState>) -> Result<()> {
    if req.files.is_empty() {
        // Not: "hiç dosya yok" ile "toplam 0 bayt dosya var" semantik olarak
        // farklı — `EmptyPayload` ikincisini anlatır, UI mesajı yanıltıcı
        // olur. Ayrı variant ile doğru i18n/log eşlemesi (Copilot review).
        return Err(HekaError::NoFilesSelected.into());
    }

    let mut plans: Vec<PlannedFile> = Vec::with_capacity(req.files.len());
    for path in &req.files {
        if !path.exists() {
            return Err(HekaError::FileNotFound(path.display().to_string()).into());
        }
        let meta = std::fs::metadata(path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dosya")
            .to_string();
        // u64 → i64 cast: meta.len() en fazla u64::MAX olabilir; i64::MAX üstü saçma
        // (8 EB). Güvenli tarafta kalmak için clamp ediyoruz; bu korumada tek bir
        // dosyanın 8 EB'den büyük olması gibi absürt bir senaryoyu elemiş oluruz.
        let raw_size = meta.len();
        if raw_size > i64::MAX as u64 {
            return Err(HekaError::FileTooLarge {
                max: i64::MAX,
                path: path.display().to_string(),
            }
            .into());
        }
        // SAFETY-CAST: `raw_size > i64::MAX as u64` üstünde checked oldu
        // (yukarıdaki `if raw_size > i64::MAX as u64`). u64 >> 1 high-bit
        // sıfır → her zaman 0..=i64::MAX. İki cast da wrap yapamaz.
        #[allow(clippy::cast_possible_wrap)]
        let size_i64 = raw_size as i64;
        #[allow(clippy::cast_possible_wrap)]
        let payload_id_i64 = (rand::thread_rng().next_u64() >> 1) as i64;
        plans.push(PlannedFile {
            path: path.clone(),
            name,
            size: size_i64,
            payload_id: payload_id_i64,
        });
    }
    // Multi-file toplamda i64 overflow olmaması için checked_add kullan.
    // 60 GB üstü senaryoda bile i64 hâlâ rahat, ama yine de savunmacı yaklaşım.
    let total_bytes: i64 = plans
        .iter()
        .try_fold(0i64, |acc, p| acc.checked_add(p.size))
        .ok_or(HekaError::ByteCountOverflow)?;
    // Bug #30: Boş dosya(lar) → total_bytes == 0 → aşağıda yüzde hesabı 0/0 olur.
    // Boş dosya göndermeyi reddetmek en açık davranış; UI kullanıcıya anlamlı hata gösterir.
    if total_bytes == 0 {
        return Err(HekaError::EmptyPayload.into());
    }
    info!(
        "[sender] hedef: {} ({}:{}), {} dosya, toplam {} bayt",
        req.device.name,
        req.device.addr,
        req.device.port,
        plans.len(),
        total_bytes
    );

    let addr = format!("{}:{}", req.device.addr, req.device.port);
    let mut socket = TcpStream::connect(&addr).await?;
    // PERF: Nagle algoritmasını devre dışı bırak — UKEY2 handshake küçük
    // frame'leri 200 ms bekletmeyi engeller. Fail non-fatal.
    if let Err(e) = socket.set_nodelay(true) {
        warn!("[sender] set_nodelay başarısız ({}): {}", addr, e);
    }
    info!("[sender] TCP bağlantı: {} ✓", addr);

    // 2) Plain ConnectionRequest
    let our_name = state
        .settings
        .read()
        .resolved_device_name(|| state.default_device_name.clone());
    let conn_req = build_connection_request(&our_name);
    frame::write_frame(&mut socket, &conn_req.encode_to_vec()).await?;
    info!("[sender] ConnectionRequest gönderildi");

    // 3) UKEY2 client handshake
    let keys = ukey2::client_handshake(&mut socket).await?;
    // SECURITY: PIN clear-text log'a yazılmaz (bkz. connection.rs).
    info!(
        "[sender] ✓ UKEY2 tamam — session fingerprint: {}",
        crate::crypto::session_fingerprint(&keys.auth_key)
    );

    // 4) Plain ConnectionResponse exchange
    let our_resp = connection::build_connection_response_accept();
    frame::write_frame(&mut socket, &our_resp.encode_to_vec()).await?;
    let peer_resp_raw =
        frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT).await?;
    let _peer_resp = OfflineFrame::decode(peer_resp_raw.as_ref())?;
    info!("[sender] ConnectionResponse değişimi tamam");

    // 5) SecureCtx kur
    let mut ctx = SecureCtx::from_keys(&keys);
    let mut assembler = PayloadAssembler::new();

    // 6) PairedKeyEncryption (biz başlatıyoruz)
    connection::send_sharing_frame(
        &mut socket,
        &mut ctx,
        &connection::build_paired_key_encryption(state.as_ref()),
    )
    .await?;
    info!("[sender] PairedKeyEncryption gönderildi");

    // 7-11) Loop — peer sharing frame'lerini işle, duruma göre sıradaki adımı tetikle
    let mut introduction_sent = false;
    let mut sent_paired_result = false;
    // RFC-0003 §3.3 — capabilities exchange tek seferlik, PairedKeyResult
    // arm'ında tetiklenir. Peer `extension_supported = false` ise atlanır.
    let mut capabilities_exchanged = false;
    // PR #112 Gemini medium: aktif capabilities transferin geri kalanında
    // (chunk-HMAC verify pipeline'ı, resume hint emit, folder bundle gating)
    // kullanılabilsin diye loop dışında yaşamalı. Default: legacy (legacy
    // peer'larla geriye uyumluluk). RFC-0003 §3.5 — `send_file_chunks` her
    // PayloadTransferFrame'den sonra `chunk_hmac_key.is_some()` ise
    // ChunkIntegrity envelope'u emit eder.
    // INVARIANT (CLAUDE.md I-2): legacy() initial value capabilities exchange
    // atlanırsa (peer extension_supported=false) kullanılan canonical default;
    // exchange tetiklenirse `outcome.active` ile overwrite olur.
    #[allow(unused_assignments)]
    let mut active_capabilities = crate::capabilities::ActiveCapabilities::legacy();
    // RFC-0003 §4.1: chunk-HMAC anahtarı capability negotiation sonrası
    // `keys.next_secret`'ten HKDF-SHA256 ile türetilir; capability inactive
    // ise None kalır → sender legacy davranışta.
    let mut chunk_hmac_key: Option<[u8; 32]> = None;
    let peer_label = req.device.name.clone();
    let transfer_id = format!("out:{}:{}", req.device.addr, req.device.port);
    let _guard = state::TransferGuard::new(Arc::clone(&state), &transfer_id);
    let cancel_token: CancellationToken = _guard.token.clone();

    loop {
        // `select!` ile cancel sinyali 60 sn'lik steady timeout'u beklemeden
        // anında algılanır. Frame read future düştüğünde socket'i zaten
        // bail yolunda terk ediyoruz.
        let raw = tokio::select! {
            biased;
            () = cancel_token.cancelled() => {
                info!("[sender] kullanıcı iptal etti");
                let cancel = connection::build_sharing_cancel();
                connection::send_sharing_frame(&mut socket, &mut ctx, &cancel)
                    .await
                    .ok();
                connection::send_disconnection(&mut socket, &mut ctx)
                    .await
                    .ok();
                state.set_progress(ProgressState::Idle);
                return Err(HekaError::UserCancelled.into());
            }
            res = frame::read_frame_timeout(&mut socket, frame::STEADY_READ_TIMEOUT) => res?,
        };
        let inner = ctx.decrypt(&raw)?;
        let offline = OfflineFrame::decode(inner.as_ref())?;
        let Some(v1) = offline.v1 else { continue };
        let ftype = v1
            .r#type
            .and_then(|t| v1_frame::FrameType::try_from(t).ok());

        match ftype {
            Some(v1_frame::FrameType::PayloadTransfer) => {
                let pt = v1
                    .payload_transfer
                    .ok_or_else(|| anyhow!("payload_transfer yok"))?;
                let Some(done) = assembler.ingest(&pt).await? else {
                    continue;
                };
                let CompletedPayload::Bytes { data, .. } = done else {
                    continue;
                };
                let Ok(sharing) = SharingFrame::decode(&data[..]) else {
                    continue;
                };
                let shv1 = sharing
                    .v1
                    .as_ref()
                    .ok_or_else(|| anyhow!("sharing v1 yok"))?;
                let stype = shv1.r#type.and_then(|t| sh_v1::FrameType::try_from(t).ok());
                match stype {
                    Some(sh_v1::FrameType::PairedKeyEncryption) => {
                        if !sent_paired_result {
                            connection::send_sharing_frame(
                                &mut socket,
                                &mut ctx,
                                &connection::build_paired_key_result(),
                            )
                            .await?;
                            sent_paired_result = true;
                            info!("[sender] PairedKeyResult gönderildi");
                        }
                    }
                    Some(sh_v1::FrameType::PairedKeyResult) => {
                        info!("[sender] peer PairedKeyResult aldı");

                        // RFC-0003 §3.3 capabilities exchange — peer mDNS
                        // TXT'te `ext=1` flag'i göndermişse (yani HekaDrop
                        // extension destekli), Introduction'dan ÖNCE
                        // capabilities swap yap. Eski Quick Share peer'ları
                        // (extension_supported=false) için exchange atlanır
                        // → mevcut Quick Share legacy akışı korunur.
                        if req.device.extension_supported && !capabilities_exchanged {
                            let outcome = crate::negotiation::negotiate_capabilities(
                                &mut socket,
                                &mut ctx,
                                crate::negotiation::DEFAULT_CAPABILITIES_TIMEOUT,
                            )
                            .await;
                            // PR #112 Gemini medium: outcome.active outer-scope
                            // `active_capabilities`'e atanır → chunk-HMAC pipeline,
                            // resume hint, folder gating buradan okur.
                            active_capabilities = outcome.active;
                            info!(
                                "[sender] active capabilities: 0x{:04x} (chunk_hmac={}, resume={}, folder={})",
                                active_capabilities.raw(),
                                active_capabilities.has(crate::capabilities::features::CHUNK_HMAC_V1),
                                active_capabilities.has(crate::capabilities::features::RESUME_V1),
                                active_capabilities.has(crate::capabilities::features::FOLDER_STREAM_V1),
                            );
                            // RFC-0003 §4.1: capability aktif ise chunk-HMAC
                            // anahtarını UKEY2 next_secret'ten türet. Sender
                            // ve receiver aynı IKM + aynı HKDF label
                            // (`"hekadrop chunk-hmac v1"`) kullandığı için
                            // çıktı sembolik olarak eşleşir.
                            if active_capabilities.has(crate::capabilities::features::CHUNK_HMAC_V1)
                            {
                                chunk_hmac_key = Some(crate::chunk_hmac::derive_chunk_hmac_key(
                                    &keys.next_secret,
                                ));
                                info!("[sender] chunk-HMAC anahtarı türetildi (RFC-0003 §4.1)");
                            }
                            // Frame loss önlemi (PR #110 high yorumu): peer
                            // extension_supported=true demiş ama legacy
                            // OfflineFrame yolladıysa plain bytes leftover'a
                            // düşer. Şimdilik state machine entegrasyonu yok
                            // → warn + skip (görünür ol, sessiz yutma).
                            if let Some(leftover) = outcome.leftover_plain {
                                tracing::warn!(
                                    "[sender] capabilities exchange — beklenmedik non-HekaDrop frame ({} byte plain) yutuldu; peer state drift riski",
                                    leftover.len(),
                                );
                            }
                            capabilities_exchanged = true;
                        }

                        if !introduction_sent {
                            let intro = build_introduction_multi(&plans);
                            connection::send_sharing_frame(&mut socket, &mut ctx, &intro).await?;
                            introduction_sent = true;
                            info!("[sender] Introduction gönderildi — {} dosya", plans.len());
                        }
                    }
                    Some(sh_v1::FrameType::Response) => {
                        let status = shv1
                            .connection_response
                            .as_ref()
                            .and_then(|r| r.status)
                            .unwrap_or(0);
                        let accepted = status == ConsentStatus::Accept as i32;
                        info!(
                            "[sender] peer Response status={} (accept={})",
                            status, accepted
                        );
                        if !accepted {
                            connection::send_disconnection(&mut socket, &mut ctx)
                                .await
                                .ok();
                            // PIN clear-text vermeyelim — auth_key fingerprint
                            // handshake'i ifşa etmeden log ilişkilendirmeye yeter.
                            return Err(HekaError::PeerRejected {
                                status,
                                fingerprint: crate::crypto::session_fingerprint(&keys.auth_key),
                            }
                            .into());
                        }
                        // 11) Tüm dosyaları sırayla gönder.
                        //
                        // RFC-0004 §5 + resume.md §1: her plan için, file
                        // chunk'larını göndermeden önce 2 sn ResumeHint
                        // bekle. Eşleşme + spec §5 invariant'ları geçerse
                        // sender `start_offset = hint.offset` ile resume
                        // eder; aksi halde ResumeReject + `start_offset = 0`
                        // legacy davranış.
                        //
                        // PR-D NOT: `RESUME_V1` capability hâlâ
                        // ALL_SUPPORTED'da değil (capabilities.rs); bu kod
                        // path'i pratikte ölü ama receiver PR-C ResumeHint
                        // emit eder ve bizim consume tarafımız sağlamla
                        // testleri yeşil tutar. Capability gate açma PR-F.
                        let our_session_id = crate::resume::session_id_i64(&keys.auth_key);
                        let known_payload_ids: Vec<i64> =
                            plans.iter().map(|p| p.payload_id).collect();
                        let mut bytes_sent: i64 = 0;
                        for plan in &plans {
                            info!(
                                "[sender] gönderiliyor: {} ({} bayt) payload_id={}",
                                plan.name, plan.size, plan.payload_id
                            );
                            let start_offset = wait_for_resume_hint_or_zero(
                                &mut socket,
                                &mut ctx,
                                plan,
                                our_session_id,
                                &known_payload_ids,
                                chunk_hmac_key.as_ref(),
                                RESUME_HINT_TIMEOUT,
                            )
                            .await;
                            send_file_chunks(
                                &mut socket,
                                &mut ctx,
                                plan.payload_id,
                                &plan.path,
                                plan.size,
                                &peer_label,
                                &plan.name,
                                bytes_sent,
                                total_bytes,
                                &cancel_token,
                                state.as_ref(),
                                chunk_hmac_key.as_ref(),
                                start_offset,
                            )
                            .await?;
                            bytes_sent += plan.size;
                        }
                        // Peer'in son chunk'ı işleyip Disconnection göndermesini
                        // bekle. Aksi halde Android "Dosya alınamadı" der çünkü
                        // alıcı son chunk'ı işlerken bizim tarafımız TCP'yi
                        // kapatmış oluyor.
                        let _ = tokio::time::timeout(
                            PEER_DISCONNECT_TIMEOUT,
                            wait_peer_disconnect(&mut socket, &mut ctx),
                        )
                        .await;
                        connection::send_disconnection(&mut socket, &mut ctx)
                            .await
                            .ok();
                        let summary = if plans.len() == 1 {
                            plans[0].name.clone()
                        } else {
                            format!("{} dosya", plans.len())
                        };
                        // Stats'i progress güncellemesinden ÖNCE yaz — böylece UI
                        // Completed'ı gördüğünde istatistikler zaten tutarlı olur.
                        //
                        // H#4 privacy: `keep_stats=false` iken disk yazımı atlanır;
                        // RAM state (UI Tanı paneli) güncellenmeye devam eder.
                        {
                            // Save'i lock dışında çalıştır — yavaş diskte UI dondurmasın.
                            // `keep_stats=false` iken snapshot clone da yapılmaz.
                            let keep = state.settings.read().keep_stats;
                            let snap_opt = {
                                let mut s = state.stats.write();
                                for plan in &plans {
                                    // .max(0) ile alt sınır 0 — sign loss imkansız.
                                    #[allow(clippy::cast_sign_loss)]
                                    let size_u = plan.size.max(0) as u64;
                                    s.record_sent(&peer_label, size_u);
                                }
                                if keep {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            };
                            if let Some(snap) = snap_opt {
                                // PR #93 + #109: try_save_stats = spawn_blocking +
                                // persistence_blocked guard.
                                state.try_save_stats(snap);
                            }
                        }
                        // Bug #31: Completed gösteriminden sonra birkaç saniye içinde
                        // otomatik Idle'a dönsün — kullanıcı pencereyi sonra açtığında
                        // eski "Tamamlandı" banner'ı kalmasın.
                        state.set_progress_completed_auto_idle(
                            summary,
                            state::DEFAULT_COMPLETED_IDLE_DELAY,
                        );
                        info!("[sender] ✓ gönderim tamamlandı");
                        return Ok(());
                    }
                    Some(sh_v1::FrameType::Cancel) => {
                        return Err(HekaError::PeerCancelled.into());
                    }
                    other => {
                        info!("[sender] sharing frame: {:?}", other);
                    }
                }
            }
            Some(v1_frame::FrameType::KeepAlive) => {
                let reply = OfflineFrame {
                    version: Some(1),
                    v1: Some(V1Frame {
                        r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                        keep_alive: Some(KeepAliveFrame::default()),
                        ..Default::default()
                    }),
                };
                let enc = ctx.encrypt(&reply.encode_to_vec())?;
                frame::write_frame(&mut socket, &enc).await?;
            }
            Some(v1_frame::FrameType::Disconnection) => {
                warn!("[sender] peer disconnect");
                return Err(HekaError::PeerDisconnected.into());
            }
            other => {
                info!("[sender] beklenmeyen: {:?}", other);
            }
        }
    }
}

/// Tek bir metin parçasını Quick Share üzerinden gönderir.
///
/// Dosya yolundaki akışın birebir aynısı — UKEY2 → `PairedKey` → Introduction →
/// Consent → `PayloadTransfer`. Tek farkı: Introduction'da `text_metadata` olur
/// (`file_metadata` yerine), payload chunk'ı `PayloadType::Bytes` tipinde tek
/// chunk (küçük metin) ya da `CHUNK_SIZE` sınırıyla parçalanmış çoklu chunk
/// halinde yollanır. Android Quick Share alıcısı Bytes payload'ı `TextType`
/// meta'sıyla eşleyip pano/URL açma akışına sokuyor.
pub struct SendTextRequest {
    pub device: DiscoveredDevice,
    pub text: String,
}

/// `TcpStream::connect` için üst sınır. Hedef cihaz kapalı/erişilemez iken
/// OS TCP SYN retry'ını ~75 sn bekletmesin diye 10 sn ile keser.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Metnin URL payload'ı olarak gönderilip gönderilmeyeceğine karar verir.
///
/// Kriter: string `http://` veya `https://` ile başlıyor (case-insensitive).
/// Peer tarafında `is_safe_url_scheme` ile aynı allow-list kullanılır — wire
/// simetrisi kasıtlı: gönderdiğimiz URL'i alıcı da açacak, göndermediklerimizi
/// (javascript:, file:, data: vb.) alıcı da reddedecek.
///
/// NOT: `send_text` çağıranı `text.trim()` ile normalize ediyor; helper yine
/// de `trim_start` yapıyor (defensive — bağımsız test'ler ve future-caller'lar
/// ham string geçebilir). UTF-8 güvenli slicing için `as_bytes` + `get`
/// kullanılır; `trimmed[..N]` direct slice çok baytlı karakter başlangıcında
/// panic yapabilir (ör. `"📎📎http://..."` — her 📎 4 byte → prefix.len()=7
/// 2. emoji'nin ortasına denk gelir).
fn detect_url_kind(text: &str) -> TextKind {
    let trimmed = text.trim_start();
    let starts_ci = |prefix: &[u8]| -> bool {
        trimmed
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    if starts_ci(b"http://") || starts_ci(b"https://") {
        TextKind::Url
    } else {
        TextKind::Text
    }
}

pub async fn send_text(
    req: SendTextRequest,
    state: Arc<AppState>,
    ctx_strings: SendCtx,
) -> Result<()> {
    // Baş/son whitespace'i baştan at: detect, title ve wire payload'ın
    // tutarlı görmesi için tek noktada normalize ediyoruz. Kullanıcı paste
    // yaparken clipboard trailing `\n` ya da `\r\n` taşıyabilir — trimsiz
    // gönderilen URL tarayıcıda malformed açılır, `url_scheme_host` title
    // ayrıştırmasını da bozar. Boş + sadece whitespace senaryoları
    // is_empty() kontrolüyle `EmptyPayload` hatasına düşer (davranış değişti:
    // eskiden "   " gönderilecekti, artık hata — niyet zaten boş göndermemek).
    let text = req.text.trim().to_string();
    if text.is_empty() {
        return Err(HekaError::EmptyPayload.into());
    }
    // `as i64` cast i64::MAX üstü uzunlukta wrap/negatif üretir; protokol
    // field'ları (`size`, `total_size`) bozulur. Pratikte bir String bu boyuta
    // ulaşamaz ama savunma amaçlı erken hata. `with_context` orijinal
    // `TryFromIntError`'ı zincirde korur (ZST ama nedeni belgeler).
    let total_bytes: i64 = i64::try_from(text.len())
        .with_context(|| format!("metin payload çok büyük: {} bayt", text.len()))?;
    // SAFETY-CAST: u64 >> 1 high-bit sıfır → daima 0..=i64::MAX.
    #[allow(clippy::cast_possible_wrap)]
    let payload_id = (rand::thread_rng().next_u64() >> 1) as i64;
    // URL şeklinde ise TextKind::Url ile etiketliyoruz: Android/alıcı share
    // sheet'te URL'i "Tarayıcıda aç" aksiyonuyla gösterir. Aksi hâlde düz TEXT.
    // Allow-list sender ve receiver'da aynı — tek taraf bypass'lansa bile
    // diğeri kapsar (defense in depth).
    let text_kind = detect_url_kind(&text) as i32;
    info!(
        "[sender] metin gönderimi: {} ({}:{}), {} bayt",
        req.device.name, req.device.addr, req.device.port, total_bytes
    );

    // Guard'ı connect'ten ÖNCE oluşturuyoruz — TCP connect takılırsa kullanıcı
    // tray'den "İptal"le durdurabilsin. Guard drop edildiğinde cancel_token
    // otomatik düşer.
    let peer_label = req.device.name.clone();
    let transfer_id = format!("out-text:{}:{}", req.device.addr, req.device.port);
    let _guard = state::TransferGuard::new(Arc::clone(&state), &transfer_id);
    let cancel_token: CancellationToken = _guard.token.clone();

    let addr = format!("{}:{}", req.device.addr, req.device.port);
    // Connect'i hem timeout hem cancel ile sarmala — erişilemez host ~75 sn
    // SYN retry bekletmesin, iptal anında çıkabilsin.
    let mut socket = tokio::select! {
        biased;
        () = cancel_token.cancelled() => return Err(HekaError::UserCancelled.into()),
        res = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)) => {
            match res {
                Ok(r) => r?,
                Err(_) => return Err(HekaError::ConnectTimeout {
                    secs: CONNECT_TIMEOUT.as_secs(),
                    addr,
                }.into()),
            }
        }
    };
    if let Err(e) = socket.set_nodelay(true) {
        warn!("[sender] set_nodelay başarısız ({}): {}", addr, e);
    }
    info!("[sender] TCP bağlantı: {} ✓", addr);

    let our_name = state
        .settings
        .read()
        .resolved_device_name(|| state.default_device_name.clone());
    let conn_req = build_connection_request(&our_name);
    frame::write_frame(&mut socket, &conn_req.encode_to_vec()).await?;

    let keys = ukey2::client_handshake(&mut socket).await?;
    info!(
        "[sender] ✓ UKEY2 tamam — session fingerprint: {}",
        crate::crypto::session_fingerprint(&keys.auth_key)
    );

    let our_resp = connection::build_connection_response_accept();
    frame::write_frame(&mut socket, &our_resp.encode_to_vec()).await?;
    let peer_resp_raw =
        frame::read_frame_timeout(&mut socket, frame::HANDSHAKE_READ_TIMEOUT).await?;
    let _peer_resp = OfflineFrame::decode(peer_resp_raw.as_ref())?;

    let mut ctx = SecureCtx::from_keys(&keys);
    let mut assembler = PayloadAssembler::new();

    connection::send_sharing_frame(
        &mut socket,
        &mut ctx,
        &connection::build_paired_key_encryption(state.as_ref()),
    )
    .await?;

    let mut introduction_sent = false;
    let mut sent_paired_result = false;

    loop {
        let raw = tokio::select! {
            biased;
            () = cancel_token.cancelled() => {
                info!("[sender] kullanıcı iptal etti (metin)");
                let cancel = connection::build_sharing_cancel();
                connection::send_sharing_frame(&mut socket, &mut ctx, &cancel).await.ok();
                connection::send_disconnection(&mut socket, &mut ctx).await.ok();
                state.set_progress(ProgressState::Idle);
                return Err(HekaError::UserCancelled.into());
            }
            res = frame::read_frame_timeout(&mut socket, frame::STEADY_READ_TIMEOUT) => res?,
        };
        let inner = ctx.decrypt(&raw)?;
        let offline = OfflineFrame::decode(inner.as_ref())?;
        let Some(v1) = offline.v1 else { continue };
        let ftype = v1
            .r#type
            .and_then(|t| v1_frame::FrameType::try_from(t).ok());

        match ftype {
            Some(v1_frame::FrameType::PayloadTransfer) => {
                let pt = v1
                    .payload_transfer
                    .ok_or_else(|| anyhow!("payload_transfer yok"))?;
                let Some(done) = assembler.ingest(&pt).await? else {
                    continue;
                };
                let CompletedPayload::Bytes { data, .. } = done else {
                    continue;
                };
                let Ok(sharing) = SharingFrame::decode(&data[..]) else {
                    continue;
                };
                let shv1 = sharing
                    .v1
                    .as_ref()
                    .ok_or_else(|| anyhow!("sharing v1 yok"))?;
                let stype = shv1.r#type.and_then(|t| sh_v1::FrameType::try_from(t).ok());
                match stype {
                    Some(sh_v1::FrameType::PairedKeyEncryption) if !sent_paired_result => {
                        connection::send_sharing_frame(
                            &mut socket,
                            &mut ctx,
                            &connection::build_paired_key_result(),
                        )
                        .await?;
                        sent_paired_result = true;
                    }
                    Some(sh_v1::FrameType::PairedKeyResult) if !introduction_sent => {
                        // URL ise peer'ın preview'ı için scheme://host kadarını koy
                        // (token'lı URL privacy): tam URL zaten bytes payload'unda
                        // gidiyor, title ayrıca PII açmasın. `url_scheme_host`
                        // fallback'i `<unparsable>` döndüğünde dump generic i18n'e
                        // düşmeden doğrudan onu title yapıyoruz — alıcı URL kabul
                        // etmiş ve allow-list zaten schema/host'u doğrulayacak.
                        let title = if text_kind == TextKind::Url as i32 {
                            crate::log_redact::url_scheme_host(&text)
                        } else {
                            ctx_strings.text_summary.clone()
                        };
                        let intro =
                            build_introduction_text(payload_id, text_kind, total_bytes, title);
                        connection::send_sharing_frame(&mut socket, &mut ctx, &intro).await?;
                        introduction_sent = true;
                        info!(
                            "[sender] Introduction gönderildi — metin ({} bayt)",
                            total_bytes
                        );
                    }
                    Some(sh_v1::FrameType::Response) => {
                        let status = shv1
                            .connection_response
                            .as_ref()
                            .and_then(|r| r.status)
                            .unwrap_or(0);
                        let accepted = status == ConsentStatus::Accept as i32;
                        if !accepted {
                            connection::send_disconnection(&mut socket, &mut ctx)
                                .await
                                .ok();
                            return Err(HekaError::PeerRejected {
                                status,
                                fingerprint: crate::crypto::session_fingerprint(&keys.auth_key),
                            }
                            .into());
                        }
                        send_text_bytes(
                            &mut socket,
                            &mut ctx,
                            payload_id,
                            text.as_bytes(),
                            &peer_label,
                            &cancel_token,
                            state.as_ref(),
                            &ctx_strings.text_summary,
                        )
                        .await?;
                        let _ = tokio::time::timeout(
                            PEER_DISCONNECT_TIMEOUT,
                            wait_peer_disconnect(&mut socket, &mut ctx),
                        )
                        .await;
                        connection::send_disconnection(&mut socket, &mut ctx)
                            .await
                            .ok();
                        {
                            let keep = state.settings.read().keep_stats;
                            let snap_opt = {
                                let mut s = state.stats.write();
                                // .max(0) ile alt sınır 0 — sign loss imkansız.
                                #[allow(clippy::cast_sign_loss)]
                                let total_bytes_u = total_bytes.max(0) as u64;
                                s.record_sent(&peer_label, total_bytes_u);
                                if keep {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            };
                            if let Some(snap) = snap_opt {
                                // Bkz. yukarı: try_save_stats helper.
                                state.try_save_stats(snap);
                            }
                        }
                        state.set_progress_completed_auto_idle(
                            ctx_strings.text_summary.clone(),
                            state::DEFAULT_COMPLETED_IDLE_DELAY,
                        );
                        info!("[sender] ✓ metin gönderimi tamamlandı");
                        return Ok(());
                    }
                    Some(sh_v1::FrameType::Cancel) => {
                        return Err(HekaError::PeerCancelled.into());
                    }
                    _ => {}
                }
            }
            Some(v1_frame::FrameType::KeepAlive) => {
                let reply = OfflineFrame {
                    version: Some(1),
                    v1: Some(V1Frame {
                        r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                        keep_alive: Some(KeepAliveFrame::default()),
                        ..Default::default()
                    }),
                };
                let enc = ctx.encrypt(&reply.encode_to_vec())?;
                frame::write_frame(&mut socket, &enc).await?;
            }
            Some(v1_frame::FrameType::Disconnection) => {
                warn!("[sender] peer disconnect (metin)");
                return Err(HekaError::PeerDisconnected.into());
            }
            _ => {}
        }
    }
}

/// Metni Bytes payload olarak gönderir. Küçük metin tek chunk + son empty
/// chunk ile biter; büyük metin `CHUNK_SIZE` sınırıyla bölünür (Android
/// tarafı her iki durumu da assembler reassembly ile ele alır).
#[allow(clippy::too_many_arguments)]
async fn send_text_bytes(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    payload_id: i64,
    data: &[u8],
    peer_label: &str,
    cancel: &CancellationToken,
    state: &AppState,
    text_summary: &str,
) -> Result<()> {
    // `as i64` cast i64::MAX üstünde wrap üretir; header'ın `total_size`'ı
    // negatif olup receiver protokol hatası verir. Pratikte erişilemez ama
    // erken ve anlamlı hata daha iyi. `with_context` orijinal hatayı zincirde korur.
    let total = i64::try_from(data.len())
        .with_context(|| format!("metin payload çok büyük: {} bayt", data.len()))?;
    let mut offset: usize = 0;
    while offset < data.len() {
        if cancel.is_cancelled() {
            return Err(HekaError::CancelledDuringChunk.into());
        }
        let end = (offset + CHUNK_SIZE).min(data.len());
        let body = data[offset..end].to_vec();
        let last_flag = 0;
        let offset_i64 = i64::try_from(offset)
            .with_context(|| format!("metin payload offset'i çok büyük: {offset}"))?;
        let wrapped = wrap_bytes_payload_transfer(payload_id, total, offset_i64, last_flag, body);
        let enc = ctx.encrypt(&wrapped.encode_to_vec())?;
        frame::write_frame(socket, &enc).await?;
        offset = end;
        let offset_i64 = i64::try_from(offset)
            .with_context(|| format!("metin payload offset'i çok büyük: {offset}"))?;
        if let Some(percent) = compute_percent(0, offset_i64, total) {
            state.set_progress(ProgressState::Receiving {
                device: peer_label.to_string(),
                file: text_summary.to_string(),
                percent,
            });
        }
    }
    // Son chunk: boş gövde, flags=1 (last).
    let last = wrap_bytes_payload_transfer(payload_id, total, total, 1, Vec::new());
    let enc = ctx.encrypt(&last.encode_to_vec())?;
    frame::write_frame(socket, &enc).await?;
    Ok(())
}

fn wrap_bytes_payload_transfer(
    id: i64,
    total_size: i64,
    offset: i64,
    flags: i32,
    body: Vec<u8>,
) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(ptf::PacketType::Data as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(id),
                    r#type: Some(PayloadType::Bytes as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    ..Default::default()
                }),
                payload_chunk: Some(PayloadChunk {
                    offset: Some(offset),
                    flags: Some(flags),
                    body: Some(body.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn build_introduction_text(
    payload_id: i64,
    kind: i32,
    size: i64,
    text_title: String,
) -> SharingFrame {
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Introduction as i32),
            introduction: Some(IntroductionFrame {
                text_metadata: vec![TextMetadata {
                    text_title: Some(text_title),
                    r#type: Some(kind),
                    payload_id: Some(payload_id),
                    size: Some(size),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_file_chunks(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    payload_id: i64,
    path: &Path,
    file_size: i64,
    peer_label: &str,
    file_name: &str,
    bytes_sent_before: i64,
    total_bytes: i64,
    cancel: &CancellationToken,
    state: &AppState,
    chunk_hmac_key: Option<&[u8; 32]>,
    start_offset: i64,
) -> Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    // RFC-0004 §5: caller `wait_for_resume_hint_or_zero` chunk-aligned
    // (`start_offset % CHUNK_SIZE == 0`) ve `0 <= start_offset <= file_size`
    // garantisini önceden sağlamış olmalı; defensive olarak bu seviyede de
    // tekrar doğrulamıyoruz (caller-side single source of truth).
    if start_offset > 0 {
        // INVARIANT: start_offset >= 0 caller tarafından doğrulandı (non-negative
        // check `wait_for_resume_hint_or_zero`'da `< 0` kontrolü ile yapıldı).
        // Burada `as u64` semantik olarak güvenli; üstteki ResumeReject yolu
        // `0` start_offset'i fallback olarak set eder.
        #[allow(clippy::cast_sign_loss)] // INVARIANT: start_offset >= 0 caller-checked
        let pos = start_offset as u64;
        file.seek(std::io::SeekFrom::Start(pos)).await?;
    }
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut offset: i64 = start_offset;
    let mut hasher = Sha256::new();
    // RFC-0003 §3.2 + RFC-0004 §3.7: chunk_index 0-tabanlı per-payload
    // monoton sayaç. Resume yolunda `start_offset / CHUNK_SIZE` ile başlar
    // (caller chunk-aligned offset garantisi verir → tam division).
    let mut chunk_index: i64 = start_offset / CHUNK_SIZE_I64;

    loop {
        // Disk read ile cancel'i paralel bekle — büyük chunk'larda ~512 KB'lık
        // read + müteakip network write cancel'e anında tepki veremezdi.
        // Cancel yolunda yarım okunmuş chunk terk edilir; zaten bail'liyoruz.
        let n = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(HekaError::CancelledDuringChunk.into()),
            res = file.read(&mut buf) => res?,
        };
        if n == 0 {
            let last = wrap_payload_transfer(payload_id, file_size, offset, 1, Bytes::new());
            let enc = ctx.encrypt(&last.encode_to_vec())?;
            frame::write_frame(socket, &enc).await?;
            let digest = hasher.finalize();
            let sha_hex = hex::encode(digest);
            info!(
                "[sender] {} gönderildi — SHA-256: {}",
                file_name,
                crate::log_redact::sha_short(&sha_hex)
            );
            break;
        }
        hasher.update(&buf[..n]);
        // Hot-path: tek kopya ile sahiplenilmiş `Bytes` üret — protobuf body alanı
        // `bytes::Bytes` (prost bytes feature) olduğundan buradan sonraki encode
        // zincirinde ek kopya oluşmaz (zero-copy reference semantics).
        let body_slice = &buf[..n];
        let body = Bytes::copy_from_slice(body_slice);
        let wrapped = wrap_payload_transfer(payload_id, file_size, offset, 0, body);
        let enc = ctx.encrypt(&wrapped.encode_to_vec())?;
        frame::write_frame(socket, &enc).await?;

        // RFC-0003 §2 ordering invariant: PayloadTransferFrame'den HEMEN
        // SONRA, başka chunk göndermeden önce ChunkIntegrity envelope'unu
        // emit et. capability gate kapalı (Some(key) yok) → legacy Quick
        // Share davranışı, tag emission yok.
        if let Some(key) = chunk_hmac_key {
            let tag =
                crate::chunk_hmac::compute_tag(key, payload_id, chunk_index, offset, body_slice)
                    .with_context(|| {
                        format!(
                    "chunk-HMAC tag compute (payload_id={payload_id}, chunk_index={chunk_index})"
                )
                    })?;
            let ci = crate::chunk_hmac::build_chunk_integrity(
                payload_id,
                chunk_index,
                offset,
                body_slice.len(),
                tag,
            )
            .with_context(|| {
                format!("ChunkIntegrity build (payload_id={payload_id}, chunk_index={chunk_index})")
            })?;
            let heka_frame = hekadrop_proto::hekadrop_ext::HekaDropFrame {
                version: crate::capabilities::ENVELOPE_VERSION,
                payload: Some(hekadrop_proto::hekadrop_ext::heka_drop_frame::Payload::ChunkTag(ci)),
            };
            let pb = heka_frame.encode_to_vec();
            let wrapped_bytes = frame::wrap_hekadrop_frame(&pb);
            let enc_tag = ctx.encrypt(&wrapped_bytes)?;
            frame::write_frame(socket, &enc_tag).await?;
            // Index taşma koruması — i64 pratik olarak taşmaz ama defensive.
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| anyhow!("chunk_index taştı (payload_id={payload_id})"))?;
        }
        // SAFETY-CAST: `n` AsyncReadExt::read'den geliyor, max CHUNK_SIZE
        // (4 KiB) ile sınırlı; usize → i64 wrap pratik olarak imkânsız.
        // Defensive: try_from + unwrap_or yerine allow + comment yeterli.
        #[allow(clippy::cast_possible_wrap)]
        let n_i64 = n as i64;
        offset += n_i64;

        // İlerleme yüzdesi: kümülatif (tüm dosyalar toplu).
        // total_bytes == 0 entry point'te bail ediliyor (Bug #30); yine de
        // `compute_percent` defansif olarak 0/0 ve overflow'u ele alır.
        if let Some(percent) = compute_percent(bytes_sent_before, offset, total_bytes) {
            state.set_progress(ProgressState::Receiving {
                device: peer_label.to_string(),
                file: file_name.to_string(),
                percent,
            });
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC-0004 — sender-side ResumeHint consume (PR-D)
// ─────────────────────────────────────────────────────────────────────────────

/// Tek bir plan için `ResumeHint` bekle + spec §5 invariant'larını uygula.
///
/// Akış:
/// 1. `RESUME_HINT_TIMEOUT` içinde frame oku → timeout → `0` (legacy fresh).
/// 2. Decrypt + magic dispatch + `HekaDropFrame` decode + `ResumeHint`
///    oneof match. Hata → `0` (silent fallback). Non-resume `HekaDrop`
///    payload (`ChunkTag`/`Capabilities`) → `0` (defensive; spec sırasız
///    hint beklemiyor; non-`HekaDrop` bytes da yutmuyoruz çünkü Response
///    sonrası sender tek başına emit eder).
/// 3. Spec §5 sender MUST listesi (sıralı):
///    - `hint.payload_id != plan.payload_id` → drop frame, return `0`
///      (peer başka payload için hint yolladı; bu plan'a uymuyor).
///    - `session_id` mismatch → `ResumeReject{SESSION_MISMATCH}` + 0
///    - `payload_id` `known_payload_ids`'de yoksa → `PAYLOAD_UNKNOWN` + 0
///    - `partial_hash.len() != 32` → drop frame (spec §5 row 4: malformed)
///    - `offset <= 0 || offset >= file_size || offset % CHUNK_SIZE != 0`
///      → `INVALID_OFFSET` + 0 (chunk-aligned plan AS-2 kararı)
///    - Hash verify (fast-path: `last_chunk_tag` + `chunk_hmac_key`, slow-
///      path: `partial_hash_streaming`) → mismatch → `HASH_MISMATCH` + 0
/// 4. Tüm kontroller geçerse `hint.offset` döndür → caller seek edecek.
#[allow(clippy::too_many_arguments)]
async fn wait_for_resume_hint_or_zero(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    plan: &PlannedFile,
    our_session_id: i64,
    known_payload_ids: &[i64],
    chunk_hmac_key: Option<&[u8; 32]>,
    timeout: Duration,
) -> i64 {
    use hekadrop_proto::hekadrop_ext::resume_reject::Reason;
    use hekadrop_proto::hekadrop_ext::{heka_drop_frame::Payload, HekaDropFrame};

    // 1. Frame oku — timeout → silent legacy fallback.
    let Ok(raw) = frame::read_frame_timeout(socket, timeout).await else {
        return 0;
    };
    let Ok(plain) = ctx.decrypt(&raw) else {
        return 0;
    };
    // 2. Magic + decode + oneof match.
    let frame::FrameKind::HekaDrop { inner } = frame::dispatch_frame_body(&plain) else {
        // Beklenmeyen non-HekaDrop frame — bu noktada peer Response Accept
        // sonrası sadece HekaDropFrame{ResumeHint} veya hiçbir şey yollar.
        // Wire protocol drift; sessizce skip edip legacy fresh'e düş.
        warn!(
            "[sender] resume bekleme penceresinde non-HekaDrop frame yutuldu (plan payload_id={})",
            plan.payload_id
        );
        return 0;
    };
    let Ok(decoded) = HekaDropFrame::decode(inner) else {
        return 0;
    };
    let Some(Payload::ResumeHint(hint)) = decoded.payload else {
        // Başka HekaDrop payload (ör. Capabilities second-frame downgrade).
        // Resume akışı için anlamsız; legacy fresh.
        return 0;
    };

    // 3a. Plan payload_id eşleşmiyorsa drop (peer multi-plan'da farklı sıraya
    //     hint emit etmiş olabilir; mevcut akış 1-plan-1-hint sıralı varsayar).
    if hint.payload_id != plan.payload_id {
        warn!(
            "[sender] ResumeHint plan ile eşleşmiyor (hint.payload_id={}, beklenen={}) — drop, fresh",
            hint.payload_id, plan.payload_id
        );
        return 0;
    }

    // 3b. Spec §5 sender MUST kontrolleri.
    if hint.session_id != our_session_id {
        info!(
            "[sender] ResumeHint session_id mismatch (peer={}, ours={}) — REJECT",
            hint.session_id, our_session_id
        );
        send_resume_reject(socket, ctx, plan.payload_id, Reason::SessionMismatch).await;
        return 0;
    }
    if !known_payload_ids.contains(&hint.payload_id) {
        info!(
            "[sender] ResumeHint payload_id={} bilinmiyor — REJECT",
            hint.payload_id
        );
        send_resume_reject(socket, ctx, plan.payload_id, Reason::PayloadUnknown).await;
        return 0;
    }
    // I-5: hint.offset peer-controlled — bounds check checked aritmetik ile.
    // Spec §5 row 3: `0 < offset < file_size`. AS-2 chunk-aligned only.
    let invalid_offset =
        hint.offset <= 0 || hint.offset >= plan.size || (hint.offset % CHUNK_SIZE_I64) != 0;
    if invalid_offset {
        info!(
            "[sender] ResumeHint offset invalid (offset={}, size={}, chunk_size={}) — REJECT",
            hint.offset, plan.size, CHUNK_SIZE_I64
        );
        send_resume_reject(socket, ctx, plan.payload_id, Reason::InvalidOffset).await;
        return 0;
    }
    if hint.partial_hash.len() != PARTIAL_HASH_LEN {
        // Spec §5 row 4: malformed → drop frame (no echo); legacy fresh.
        warn!(
            "[sender] ResumeHint partial_hash uzunluğu {} ≠ 32 — drop, fresh",
            hint.partial_hash.len()
        );
        return 0;
    }

    // 3c. Hash verify — fast-path (chunk-HMAC) varsa O(1), aksi halde
    //     slow-path full SHA-256 streaming hash recompute.
    let verify_ok = match (chunk_hmac_key, hint.last_chunk_tag.len()) {
        (Some(key), PARTIAL_HASH_LEN) => verify_last_chunk_tag(
            &plan.path,
            plan.payload_id,
            hint.offset,
            &hint.last_chunk_tag,
            key,
        )
        .await
        .unwrap_or(false),
        _ => verify_partial_hash_full(&plan.path, hint.offset, &hint.partial_hash)
            .await
            .unwrap_or(false),
    };

    if !verify_ok {
        info!(
            "[sender] ResumeHint hash verify FAIL (payload_id={}, offset={}) — REJECT",
            hint.payload_id, hint.offset
        );
        send_resume_reject(socket, ctx, plan.payload_id, Reason::HashMismatch).await;
        return 0;
    }

    info!(
        "[sender] ResumeHint kabul edildi — resume offset={} (payload_id={})",
        hint.offset, hint.payload_id
    );
    hint.offset
}

/// `ResumeReject` envelope'unu inşa et + secure channel üstünden yolla.
///
/// Hata yutulur (`.ok()` semantiği): reject best-effort'tür; yazılamasa bile
/// sender legacy `start_offset = 0` ile devam eder. Receiver hint timeout
/// veya hash mismatch ile `.part`/`.meta` cleanup yapacak (spec §6 matrix).
async fn send_resume_reject(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    payload_id: i64,
    reason: hekadrop_proto::hekadrop_ext::resume_reject::Reason,
) {
    let reject = hekadrop_proto::hekadrop_ext::ResumeReject {
        payload_id,
        reason: reason as i32,
    };
    let envelope = crate::capabilities::build_resume_reject_frame(reject);
    let pb = envelope.encode_to_vec();
    let wrapped = frame::wrap_hekadrop_frame(&pb);
    let Ok(enc) = ctx.encrypt(&wrapped) else {
        warn!(
            "[sender] ResumeReject encrypt başarısız (payload_id={}, reason={:?}) — drop",
            payload_id, reason
        );
        return;
    };
    if let Err(e) = frame::write_frame(socket, &enc).await {
        warn!(
            "[sender] ResumeReject write başarısız (payload_id={}, reason={:?}): {}",
            payload_id, reason, e
        );
    }
}

/// Slow-path defense-in-depth: yerel `path[0..offset]` üstünde streaming
/// SHA-256 → peer `partial_hash` ile constant-time karşılaştır.
///
/// `partial_hash_streaming` blocking I/O yapar (`BufReader::read_exact`);
/// async runtime'ı bloklamamak için `spawn_blocking` ile sarmalı.
/// Hata → `Ok(false)` (silent reject; resume best-effort).
async fn verify_partial_hash_full(
    path: &Path,
    offset: i64,
    expected: &[u8],
) -> std::io::Result<bool> {
    use subtle::ConstantTimeEq;
    // INVARIANT: caller `offset > 0` kontrolünü zaten yaptı (§5 row 3);
    // ayrıca spec_offset >= 0 garanti, sign loss yok.
    #[allow(clippy::cast_sign_loss)] // INVARIANT: offset > 0 caller-checked
    let off_u = offset as u64;
    let owned_path = path.to_path_buf();
    let local = tokio::task::spawn_blocking(move || {
        crate::resume::partial_hash_streaming(&owned_path, off_u)
    })
    .await
    .map_err(std::io::Error::other)??;
    Ok(local.ct_eq(expected).into())
}

/// Fast-path (RFC-0004 §3.1 + §5 row 6): `last_chunk_tag` + chunk-HMAC key
/// mevcutsa, sadece son verified chunk'ın HMAC tag'ini hesapla + constant-
/// time karşılaştır → O(1) verify, full SHA-256 atlanır.
///
/// Son chunk index = `(offset / CHUNK_SIZE) - 1`; chunk başlangıcı
/// `(offset - chunk_len)` ofsetinde. Chunk-aligned offset garantili
/// (caller §5 row 3 `INVALID_OFFSET` kontrolünde rejected ediyor); bu
/// fonksiyon `offset == CHUNK_SIZE * k, k >= 1` varsayar.
///
/// Hata → `Ok(false)` (silent reject; resume best-effort).
async fn verify_last_chunk_tag(
    path: &Path,
    payload_id: i64,
    offset: i64,
    expected_tag: &[u8],
    key: &[u8; 32],
) -> std::io::Result<bool> {
    use subtle::ConstantTimeEq;
    use tokio::io::AsyncReadExt as _;

    // INVARIANT: caller offset > 0 + chunk-aligned + < file_size garantisi
    // verdi → last_chunk_index >= 0, last_chunk_start >= 0.
    let last_chunk_index = (offset / CHUNK_SIZE_I64) - 1;
    let last_chunk_start = last_chunk_index * CHUNK_SIZE_I64;
    // Chunk uzunluğu sabit CHUNK_SIZE — caller offset == k * CHUNK_SIZE
    // garantisi verdi (k >= 1, k*CHUNK_SIZE < file_size). Last full chunk
    // o yüzden tam CHUNK_SIZE byte.
    let chunk_len = CHUNK_SIZE;

    let mut file = tokio::fs::File::open(path).await?;
    #[allow(clippy::cast_sign_loss)] // INVARIANT: last_chunk_start >= 0 caller-checked
    let pos = last_chunk_start as u64;
    file.seek(std::io::SeekFrom::Start(pos)).await?;
    let mut buf = vec![0u8; chunk_len];
    file.read_exact(&mut buf).await?;

    let key_owned: [u8; 32] = *key;
    let Ok(computed) = crate::chunk_hmac::compute_tag(
        &key_owned,
        payload_id,
        last_chunk_index,
        last_chunk_start,
        &buf,
    ) else {
        return Ok(false);
    };
    Ok(computed.ct_eq(expected_tag).into())
}

/// `CHUNK_SIZE` `i64` cinsinden — `i64::from` ile maliyetsiz cast için.
/// `CHUNK_SIZE = 524288 < i64::MAX` olduğundan literal cast wrap'siz.
// SAFETY-CAST: CHUNK_SIZE compile-time literal 524288 << i64::MAX, wrap imkansız.
#[allow(clippy::cast_possible_wrap)] // INVARIANT: CHUNK_SIZE = 512 KiB literal
const CHUNK_SIZE_I64: i64 = CHUNK_SIZE as i64;

/// SHA-256 / HMAC-SHA256 tag length (32 byte) — `partial_hash` ve
/// `last_chunk_tag` field'larının sabit boyutu (RFC-0004 §3.1).
const PARTIAL_HASH_LEN: usize = 32;

/// Son chunk'tan sonra peer'in `Disconnection` frame'ini göndermesini veya
/// bağlantının EOF/okuma hatasıyla kapanmasını bekler. Arada gelen
/// `KeepAlive` çağrılarına yanıt verir; diğer frame tipleri yok sayılır.
/// Böylece Android dosyayı diske yazıp doğrularken bizim tarafımız TCP'yi
/// kapatmış olmaz. Üst sınır caller'daki [`PEER_DISCONNECT_TIMEOUT`]
/// sarmalayıcısıyla uygulanır.
async fn wait_peer_disconnect(socket: &mut TcpStream, ctx: &mut SecureCtx) -> Result<()> {
    loop {
        let Ok(raw) = frame::read_frame(socket).await else {
            return Ok(());
        };
        let Ok(inner) = ctx.decrypt(&raw) else {
            continue;
        };
        let Ok(offline) = OfflineFrame::decode(inner.as_ref()) else {
            continue;
        };
        let Some(v1) = offline.v1 else { continue };
        let ftype = v1
            .r#type
            .and_then(|t| v1_frame::FrameType::try_from(t).ok());
        match ftype {
            Some(v1_frame::FrameType::Disconnection) => return Ok(()),
            Some(v1_frame::FrameType::KeepAlive) => {
                let reply = OfflineFrame {
                    version: Some(1),
                    v1: Some(V1Frame {
                        r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                        keep_alive: Some(KeepAliveFrame::default()),
                        ..Default::default()
                    }),
                };
                let enc = ctx.encrypt(&reply.encode_to_vec())?;
                frame::write_frame(socket, &enc).await?;
            }
            _ => {}
        }
    }
}

fn wrap_payload_transfer(
    id: i64,
    total_size: i64,
    offset: i64,
    flags: i32,
    body: Bytes,
) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(ptf::PacketType::Data as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(id),
                    r#type: Some(PayloadType::File as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    ..Default::default()
                }),
                payload_chunk: Some(PayloadChunk {
                    offset: Some(offset),
                    flags: Some(flags),
                    body: Some(body),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn build_introduction_multi(plans: &[PlannedFile]) -> SharingFrame {
    let files: Vec<FileMetadata> = plans
        .iter()
        .map(|p| FileMetadata {
            name: Some(p.name.clone()),
            r#type: Some(FileKind::Unknown as i32),
            payload_id: Some(p.payload_id),
            size: Some(p.size),
            mime_type: Some(guess_mime(&p.name).to_string()),
            ..Default::default()
        })
        .collect();
    SharingFrame {
        version: Some(ShVersion::V1 as i32),
        v1: Some(ShV1Frame {
            r#type: Some(sh_v1::FrameType::Introduction as i32),
            introduction: Some(IntroductionFrame {
                file_metadata: files,
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn guess_mime(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "txt" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

/// Kümülatif byte'lardan [0, 100] aralığında yüzde hesaplar.
///
/// Döner `None` olursa hesap yapılmadı demektir (sıfıra bölme, taşma vb.) —
/// UI'a yeni bir progress update gönderilmez, eski değer kalır.
///
/// - `total` sıfır ya da negatifse `None`: anlamlı bir yüzde yok.
/// - Ara çarpım `i64` taşarsa `None`: dev dosyalarda savunma.
/// - Sonuç `[0, 100]` aralığına `clamp` edilir (floating-point olmadan).
fn compute_percent(bytes_before: i64, offset: i64, total: i64) -> Option<u8> {
    if total <= 0 {
        return None;
    }
    let cumulative = bytes_before.checked_add(offset)?;
    let product = cumulative.checked_mul(100)?;
    let raw = product.checked_div(total)?;
    // clamp(0, 100) sonrası değer 0..=100 aralığında — sign loss imkansız.
    #[allow(clippy::cast_sign_loss)]
    let percent = raw.clamp(0, 100) as u8;
    Some(percent)
}

fn build_connection_request(our_name: &str) -> OfflineFrame {
    let endpoint_id = config::random_endpoint_id();
    let endpoint_info = config::endpoint_info(our_name);

    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::ConnectionRequest as i32),
            connection_request: Some(ConnectionRequestFrame {
                endpoint_id: Some(
                    std::str::from_utf8(&endpoint_id)
                        .unwrap_or("HEKA")
                        .to_string(),
                ),
                endpoint_name: Some(our_name.to_string()),
                endpoint_info: Some(endpoint_info.into()),
                mediums: vec![Medium::WifiLan as i32],
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

#[cfg(test)]
// Test profile relaxation (CLAUDE.md I-2): hardcoded fixture verisi (CHUNK_SIZE *
// 2 → i64 cast vb.) için per-statement allow tutarsız olur; module-bazlı dar
// scope. Production lint'leri bozmaz çünkü `#[cfg(test)]` altındadır.
#[allow(clippy::cast_possible_wrap, clippy::doc_markdown)]
mod tests {
    use super::*;

    // Bug #30: total == 0 durumunda yüzde hesaplanmaz → panic/NaN riski yok.
    #[test]
    fn compute_percent_total_zero_returns_none() {
        assert_eq!(compute_percent(0, 0, 0), None);
        assert_eq!(compute_percent(100, 50, 0), None);
    }

    // Bug #30 kenar durum: negatif total (kurallara aykırı veri) sessizce atlanır.
    #[test]
    fn compute_percent_negative_total_returns_none() {
        assert_eq!(compute_percent(0, 0, -1), None);
    }

    #[test]
    fn compute_percent_basic_progression() {
        // 0/1000 = 0%
        assert_eq!(compute_percent(0, 0, 1000), Some(0));
        // 500/1000 = 50%
        assert_eq!(compute_percent(0, 500, 1000), Some(50));
        // 1000/1000 = 100%
        assert_eq!(compute_percent(500, 500, 1000), Some(100));
    }

    #[test]
    fn compute_percent_clamps_to_100() {
        // Offset total'dan büyükse (patolojik giriş) sonuç 100'e clamp edilir,
        // asla 100'ü aşmaz.
        assert_eq!(compute_percent(0, 10_000, 1000), Some(100));
        assert_eq!(compute_percent(2000, 0, 1000), Some(100));
    }

    #[test]
    fn compute_percent_overflow_safe_on_huge_values() {
        // cumulative * 100 i64'u taşıracaksa None; panic YOK.
        // i64::MAX / 100 + 1 → çarparken kesin taşar.
        let huge = (i64::MAX / 100) + 1;
        assert_eq!(compute_percent(huge, 0, i64::MAX), None);
    }

    #[test]
    fn compute_percent_large_realistic_transfer() {
        // 60 GB transfer simülasyonu — overflow olmadan doğru yüzde.
        let total: i64 = 60 * 1024 * 1024 * 1024;
        let half = total / 2;
        assert_eq!(compute_percent(0, half, total), Some(50));
        assert_eq!(compute_percent(half, half, total), Some(100));
    }

    #[test]
    fn guess_mime_known_and_unknown() {
        assert_eq!(guess_mime("foto.jpg"), "image/jpeg");
        assert_eq!(guess_mime("FOTO.JPEG"), "image/jpeg");
        assert_eq!(guess_mime("video.mp4"), "video/mp4");
        assert_eq!(guess_mime("belge.pdf"), "application/pdf");
        assert_eq!(guess_mime("bilinmiyor.xyz"), "application/octet-stream");
        assert_eq!(guess_mime("uzantisiz"), "application/octet-stream");
    }

    // Regression: text_metadata alanları payload_id/size/type doğru eşlenmeli,
    // receiver introduction'ı dolu (planned_texts boş değil) olarak görsün.
    #[test]
    fn build_introduction_text_alanlari_dogru_doldurur() {
        let frame = build_introduction_text(42, TextKind::Text as i32, 128, "özet".to_string());
        assert_eq!(frame.version, Some(ShVersion::V1 as i32));
        let v1 = frame.v1.expect("v1 frame yok");
        assert_eq!(v1.r#type, Some(sh_v1::FrameType::Introduction as i32));
        let intro = v1.introduction.expect("introduction yok");
        assert!(intro.file_metadata.is_empty());
        assert_eq!(intro.text_metadata.len(), 1);
        let m = &intro.text_metadata[0];
        assert_eq!(m.payload_id, Some(42));
        assert_eq!(m.size, Some(128));
        assert_eq!(m.r#type, Some(TextKind::Text as i32));
        assert_eq!(m.text_title.as_deref(), Some("özet"));
    }

    // URL auto-detection: http/https başlayan metin `Url` tipine etiketlenmeli,
    // diğer şemalar ve düz metin `Text` olarak kalmalı. Allow-list wire
    // simetrisinin sender yarısı bu testle kilitlenir.
    #[test]
    fn detect_url_kind_http_https_yakalar() {
        // Pozitif — http(s) allow-list'e giriyor
        assert_eq!(detect_url_kind("http://example.com"), TextKind::Url);
        assert_eq!(detect_url_kind("https://example.com"), TextKind::Url);
        assert_eq!(detect_url_kind("HTTPS://X.COM/path"), TextKind::Url);
        assert_eq!(
            detect_url_kind("  https://leading-ws.example"),
            TextKind::Url
        );
        // Negatif — reddedilen şemalar ve düz metin Text olmalı
        assert_eq!(detect_url_kind("javascript:alert(1)"), TextKind::Text);
        assert_eq!(detect_url_kind("file:///etc/passwd"), TextKind::Text);
        assert_eq!(detect_url_kind("data:text/html,<script/>"), TextKind::Text);
        assert_eq!(detect_url_kind("zoom-us://join?id=1"), TextKind::Text);
        assert_eq!(detect_url_kind("merhaba dünya"), TextKind::Text);
        assert_eq!(detect_url_kind("http"), TextKind::Text);
        assert_eq!(detect_url_kind(""), TextKind::Text);
    }

    // Regression (gemini-code-assist PR-82 HIGH): multi-byte karakter başında
    // direct slice `trimmed[..prefix.len()]` UTF-8 boundary'ye denk gelmezse
    // panic eder. `"📎📎http://..."` — her 📎 4 byte, prefix.len() `http://`
    // için 7 → 2. emoji'nin ortasında kesim → RUNTIME PANIC. Panik-güvenli
    // `as_bytes().get(..)` + `eq_ignore_ascii_case` ile çözüldü; bu test
    // sabitleyici. Fuzz harness'ı da aynı yüzeyi kontrol ediyor.
    #[test]
    fn detect_url_kind_multibyte_prefix_panik_etmez() {
        // Emoji başlangıç + URL — ham string dev boundary ihlali üretir, panic olmamalı
        assert_eq!(detect_url_kind("📎📎http://example.com"), TextKind::Text);
        assert_eq!(detect_url_kind("🔗 https://x.com"), TextKind::Text);
        // Kiril prefix — П = 2 byte, `https://` 8 byte, slice head [..8] 2. П'nin sonrasını içerir
        assert_eq!(detect_url_kind("Пhttps://x.com"), TextKind::Text);
        // Çok kısa string — prefix.len() text boyunu aşar, `get` None döner
        assert_eq!(detect_url_kind("é"), TextKind::Text); // 2 byte
        assert_eq!(detect_url_kind("ééé"), TextKind::Text); // 6 byte
        assert_eq!(detect_url_kind("éééé"), TextKind::Text); // 8 byte
    }

    // RFC 0002 regression: URL için `text_title` tam URL değil scheme://host
    // preview'ı olmalı (token'lı URL privacy). Tam URL payload bytes'ında
    // gönderiliyor; title Android paylaşım geçmişinde kalıcı olabileceği için
    // sadece scheme + host tutuyoruz.
    #[test]
    fn build_introduction_text_url_title_scheme_host_preview() {
        let url = "https://example.com/path?token=abc123";
        let title = crate::log_redact::url_scheme_host(url);
        let frame = build_introduction_text(7, TextKind::Url as i32, 42, title.clone());
        let m = &frame
            .v1
            .expect("v1")
            .introduction
            .expect("intro")
            .text_metadata[0];
        assert_eq!(m.r#type, Some(TextKind::Url as i32));
        assert_eq!(m.text_title.as_deref(), Some(title.as_str()));
        // log_redact::url_scheme_host zaten token-strip ediyor — regression için
        // title'da "token" geçmemeli.
        assert!(
            !m.text_title.as_deref().unwrap_or("").contains("token"),
            "title URL token'ı içermemeli: {:?}",
            m.text_title
        );
    }

    // Regression: Bytes payload header type File DEĞİL, Bytes olmalı —
    // receiver Bytes dışı payload'ı dosya olarak yazmaya çalışır.
    #[test]
    fn wrap_bytes_payload_transfer_bytes_header_ve_chunk_uretir() {
        let frame = wrap_bytes_payload_transfer(7, 10, 3, 0, vec![1, 2, 3]);
        let v1 = frame.v1.expect("v1 yok");
        assert_eq!(v1.r#type, Some(v1_frame::FrameType::PayloadTransfer as i32));
        let pt = v1.payload_transfer.expect("payload_transfer yok");
        let hdr = pt.payload_header.expect("header yok");
        assert_eq!(hdr.r#type, Some(PayloadType::Bytes as i32));
        assert_eq!(hdr.id, Some(7));
        assert_eq!(hdr.total_size, Some(10));
        let ch = pt.payload_chunk.expect("chunk yok");
        assert_eq!(ch.offset, Some(3));
        assert_eq!(ch.flags, Some(0));
        assert_eq!(ch.body.as_deref(), Some(&[1u8, 2, 3][..]));
    }

    // ─────────────────────────────────────────────────────────────────────
    // RFC-0004 PR-D — sender ResumeHint consume + verify + seek
    // ─────────────────────────────────────────────────────────────────────

    use crate::ukey2::DerivedKeys;
    use hekadrop_proto::hekadrop_ext::resume_reject::Reason;
    use hekadrop_proto::hekadrop_ext::{
        heka_drop_frame::Payload as ExtPayload, HekaDropFrame, ResumeHint, ResumeReject,
    };
    use std::io::Write as _;
    use tokio::net::{TcpListener, TcpStream};

    /// `negotiation.rs` test'lerinden kopya — server ↔ client `SecureCtx`
    /// pair'i. UKEY2 simetrisini taklit eder (server.encrypt = client.decrypt).
    fn matched_secure_ctx_pair() -> (SecureCtx, SecureCtx) {
        let key_a = [0x42u8; 32];
        let key_b = [0x55u8; 32];
        let hmac_a = [0xAAu8; 32];
        let hmac_b = [0xBBu8; 32];
        let auth = [0x77u8; 32];
        let next = [0x99u8; 32];

        let server_keys = DerivedKeys {
            decrypt_key: key_a,
            recv_hmac_key: hmac_a,
            encrypt_key: key_b,
            send_hmac_key: hmac_b,
            auth_key: auth,
            pin_code: "0000".to_string(),
            next_secret: next,
        };
        let client_keys = DerivedKeys {
            decrypt_key: key_b,
            recv_hmac_key: hmac_b,
            encrypt_key: key_a,
            send_hmac_key: hmac_a,
            auth_key: auth,
            pin_code: "0000".to_string(),
            next_secret: next,
        };
        (
            SecureCtx::from_keys(&server_keys),
            SecureCtx::from_keys(&client_keys),
        )
    }

    /// Deterministic dosya yarat — `seed`'den türetilen `total_size` bayt.
    fn write_test_file(total_size: usize, seed: u8) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payload.bin");
        let mut file = std::fs::File::create(&path).expect("create");
        // Tekrarlayan, predictable byte pattern; chunk-aligned hash hesabı için.
        let buf: Vec<u8> = (0..total_size)
            .map(|i| ((i as u32).wrapping_mul(31).wrapping_add(u32::from(seed)) & 0xFF) as u8)
            .collect();
        file.write_all(&buf).expect("write");
        file.sync_all().expect("sync");
        (dir, path)
    }

    /// Peer-side: ResumeHint envelope'u şifreleyip wire'a yaz.
    async fn send_resume_hint(socket: &mut TcpStream, ctx: &mut SecureCtx, hint: ResumeHint) {
        let envelope = crate::capabilities::build_resume_hint_frame(hint);
        let pb = envelope.encode_to_vec();
        let wrapped = frame::wrap_hekadrop_frame(&pb);
        let enc = ctx.encrypt(&wrapped).expect("encrypt hint");
        frame::write_frame(socket, &enc).await.expect("write hint");
    }

    /// Peer-side: sender'dan dönen frame'i decrypt + dispatch + decode et.
    /// Sadece HekaDropFrame (ResumeReject) bekliyoruz; başka tip → panic.
    async fn read_resume_reject(socket: &mut TcpStream, ctx: &mut SecureCtx) -> ResumeReject {
        let raw = frame::read_frame_timeout(socket, Duration::from_secs(2))
            .await
            .expect("read reject");
        let plain = ctx.decrypt(&raw).expect("decrypt reject");
        let frame::FrameKind::HekaDrop { inner } = frame::dispatch_frame_body(&plain) else {
            panic!("HekaDropFrame magic bekleniyor");
        };
        let envelope = HekaDropFrame::decode(inner).expect("decode envelope");
        let Some(ExtPayload::ResumeReject(reject)) = envelope.payload else {
            panic!("ResumeReject oneof bekleniyor: {envelope:?}");
        };
        reject
    }

    /// Plan helper — payload_id sabit, dosya yarat + plan struct kur.
    fn plan_for(path: std::path::PathBuf, payload_id: i64, size: i64) -> PlannedFile {
        PlannedFile {
            path,
            name: "payload.bin".to_string(),
            size,
            payload_id,
        }
    }

    /// Hash recompute helper — `partial_hash_streaming` ile aynı output.
    fn hash_prefix(path: &Path, offset: u64) -> [u8; 32] {
        crate::resume::partial_hash_streaming(path, offset).expect("hash prefix")
    }

    /// Test 1 — happy path: chunk-aligned offset + matching partial_hash →
    /// `wait_for_resume_hint_or_zero` `hint.offset` döndürür (resume seek
    /// için), reject yollanmaz.
    #[tokio::test]
    async fn sender_resume_happy_path_chunk_aligned() {
        // 2 chunk = 1 MiB total; resume offset = 1 chunk (512 KiB).
        let total_size = CHUNK_SIZE * 2;
        let resume_offset = CHUNK_SIZE as i64;
        let payload_id: i64 = 0xABCD_1234;

        let (_dir, path) = write_test_file(total_size, 7);
        let plan = plan_for(path.clone(), payload_id, total_size as i64);
        let our_session_id: i64 = 0x1111_2222_3333_4444;
        let known = vec![payload_id];
        let expected_hash = hash_prefix(&path, resume_offset as u64);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        // Peer (receiver simulation): connect + send ResumeHint.
        let peer_session = our_session_id;
        let peer_task = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let hint = ResumeHint {
                session_id: peer_session,
                payload_id,
                offset: resume_offset,
                partial_hash: expected_hash.to_vec().into(),
                capabilities_version: crate::capabilities::CAPABILITIES_VERSION,
                last_chunk_tag: Vec::new().into(),
            };
            send_resume_hint(&mut s, &mut client_ctx, hint).await;
            // Server tarafında reject yollanmamalı; peer 200 ms bekleyip kapanır.
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Reject yokmuş demek için socket'i kapatıyoruz; sender server'da
            // zaten dönmüş olmalı (read sonrası).
        });

        // Sender (server): accept + wait_for_resume_hint_or_zero.
        let (mut sender_socket, _) = listener.accept().await.unwrap();
        let start_offset = wait_for_resume_hint_or_zero(
            &mut sender_socket,
            &mut server_ctx,
            &plan,
            our_session_id,
            &known,
            None, // no chunk-HMAC key → slow-path full SHA-256
            Duration::from_secs(2),
        )
        .await;
        peer_task.await.unwrap();

        assert_eq!(
            start_offset, resume_offset,
            "happy path: hint kabul edilmeli, start_offset = hint.offset"
        );
    }

    /// Test 2 — yanlış partial_hash → ResumeReject{HASH_MISMATCH} +
    /// `start_offset = 0`.
    #[tokio::test]
    async fn sender_resume_hash_mismatch_emits_reject() {
        let total_size = CHUNK_SIZE * 2;
        let resume_offset = CHUNK_SIZE as i64;
        let payload_id: i64 = 0x9999;

        let (_dir, path) = write_test_file(total_size, 11);
        let plan = plan_for(path, payload_id, total_size as i64);
        let our_session_id: i64 = 0xAAAA_BBBB;
        let known = vec![payload_id];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        let peer_task = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let hint = ResumeHint {
                session_id: our_session_id,
                payload_id,
                offset: resume_offset,
                // Yanlış hash — local file'dan farklı, deliberate corruption.
                partial_hash: vec![0xFFu8; 32].into(),
                capabilities_version: crate::capabilities::CAPABILITIES_VERSION,
                last_chunk_tag: Vec::new().into(),
            };
            send_resume_hint(&mut s, &mut client_ctx, hint).await;
            // ResumeReject{HASH_MISMATCH} bekle.
            let reject = read_resume_reject(&mut s, &mut client_ctx).await;
            assert_eq!(reject.payload_id, payload_id);
            assert_eq!(reject.reason, Reason::HashMismatch as i32);
        });

        let (mut sender_socket, _) = listener.accept().await.unwrap();
        let start_offset = wait_for_resume_hint_or_zero(
            &mut sender_socket,
            &mut server_ctx,
            &plan,
            our_session_id,
            &known,
            None,
            Duration::from_secs(2),
        )
        .await;
        peer_task.await.unwrap();

        assert_eq!(start_offset, 0, "hash mismatch → fresh start (offset 0)");
    }

    /// Test 3 — yanlış session_id → ResumeReject{SESSION_MISMATCH} + 0.
    #[tokio::test]
    async fn sender_resume_session_mismatch_drops() {
        let total_size = CHUNK_SIZE * 2;
        let resume_offset = CHUNK_SIZE as i64;
        let payload_id: i64 = 0x1234;

        let (_dir, path) = write_test_file(total_size, 13);
        let plan = plan_for(path, payload_id, total_size as i64);
        let our_session_id: i64 = 0xDEAD_BEEF;
        let known = vec![payload_id];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        let peer_task = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let hint = ResumeHint {
                // Bizim session_id'mizden farklı — peer state drift.
                session_id: our_session_id ^ 0xFFFF,
                payload_id,
                offset: resume_offset,
                partial_hash: vec![0xAA; 32].into(),
                capabilities_version: crate::capabilities::CAPABILITIES_VERSION,
                last_chunk_tag: Vec::new().into(),
            };
            send_resume_hint(&mut s, &mut client_ctx, hint).await;
            let reject = read_resume_reject(&mut s, &mut client_ctx).await;
            assert_eq!(reject.payload_id, payload_id);
            assert_eq!(reject.reason, Reason::SessionMismatch as i32);
        });

        let (mut sender_socket, _) = listener.accept().await.unwrap();
        let start_offset = wait_for_resume_hint_or_zero(
            &mut sender_socket,
            &mut server_ctx,
            &plan,
            our_session_id,
            &known,
            None,
            Duration::from_secs(2),
        )
        .await;
        peer_task.await.unwrap();

        assert_eq!(start_offset, 0, "session mismatch → fresh start");
    }

    /// Test 4 — invalid offset (chunk-aligned değil) → ResumeReject{
    /// INVALID_OFFSET} + 0.
    #[tokio::test]
    async fn sender_resume_invalid_offset_rejects() {
        let total_size = CHUNK_SIZE * 2;
        // Chunk boundary'ye denk gelmiyor — AS-2 reject etmeli.
        let resume_offset = (CHUNK_SIZE as i64) + 1;
        let payload_id: i64 = 0x5555;

        let (_dir, path) = write_test_file(total_size, 17);
        let plan = plan_for(path, payload_id, total_size as i64);
        let our_session_id: i64 = 0x4242;
        let known = vec![payload_id];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        let peer_task = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let hint = ResumeHint {
                session_id: our_session_id,
                payload_id,
                offset: resume_offset,
                partial_hash: vec![0u8; 32].into(),
                capabilities_version: crate::capabilities::CAPABILITIES_VERSION,
                last_chunk_tag: Vec::new().into(),
            };
            send_resume_hint(&mut s, &mut client_ctx, hint).await;
            let reject = read_resume_reject(&mut s, &mut client_ctx).await;
            assert_eq!(reject.payload_id, payload_id);
            assert_eq!(reject.reason, Reason::InvalidOffset as i32);
        });

        let (mut sender_socket, _) = listener.accept().await.unwrap();
        let start_offset = wait_for_resume_hint_or_zero(
            &mut sender_socket,
            &mut server_ctx,
            &plan,
            our_session_id,
            &known,
            None,
            Duration::from_secs(2),
        )
        .await;
        peer_task.await.unwrap();

        assert_eq!(start_offset, 0, "non-aligned offset → fresh start");
    }

    /// Test 5 — fast-path: `chunk_hmac_key` + `last_chunk_tag` (32 byte) →
    /// sadece son chunk HMAC verify edilir, full SHA-256 atlanır. Doğru
    /// tag → resume kabul; yanlış tag → reject.
    #[tokio::test]
    async fn sender_resume_last_chunk_tag_fastpath() {
        let total_size = CHUNK_SIZE * 2;
        let resume_offset = CHUNK_SIZE as i64; // 1 tam chunk
        let payload_id: i64 = 0x77AA;

        let (_dir, path) = write_test_file(total_size, 23);
        let plan = plan_for(path.clone(), payload_id, total_size as i64);
        let our_session_id: i64 = 0xBEEF_CAFE;
        let known = vec![payload_id];
        let chunk_hmac_key: [u8; 32] = [0xC0u8; 32];

        // Last full chunk = chunk_index 0 (offset 0..CHUNK_SIZE).
        let last_chunk_index: i64 = 0;
        let last_chunk_start: i64 = 0;
        let chunk_bytes = std::fs::read(&path).unwrap()[..CHUNK_SIZE].to_vec();
        let expected_tag = crate::chunk_hmac::compute_tag(
            &chunk_hmac_key,
            payload_id,
            last_chunk_index,
            last_chunk_start,
            &chunk_bytes,
        )
        .expect("compute tag");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut server_ctx, mut client_ctx) = matched_secure_ctx_pair();

        // Hint: deliberately yanlış partial_hash (slow-path olsa fail ederdi);
        // last_chunk_tag DOĞRU. Fast-path tetiklendiği için tag ile karar verilmeli.
        let peer_task = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let hint = ResumeHint {
                session_id: our_session_id,
                payload_id,
                offset: resume_offset,
                partial_hash: vec![0xFFu8; 32].into(), // slow-path uygulansa fail
                capabilities_version: crate::capabilities::CAPABILITIES_VERSION,
                last_chunk_tag: expected_tag.to_vec().into(),
            };
            send_resume_hint(&mut s, &mut client_ctx, hint).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (mut sender_socket, _) = listener.accept().await.unwrap();
        let start_offset = wait_for_resume_hint_or_zero(
            &mut sender_socket,
            &mut server_ctx,
            &plan,
            our_session_id,
            &known,
            Some(&chunk_hmac_key),
            Duration::from_secs(2),
        )
        .await;
        peer_task.await.unwrap();

        assert_eq!(
            start_offset, resume_offset,
            "fast-path: doğru last_chunk_tag → resume kabul (full SHA-256 atlandı)"
        );
    }
}
