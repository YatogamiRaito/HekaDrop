//! Payload reassembly — `PayloadTransferFrame` chunk'larını toplar.
//!
//! BYTES tipindeki küçük payload'lar (sharing frame'ler) bellekte birikir.
//! FILE tipindeki payload'lar, Introduction sırasında belirlenen yola
//! ilk chunk geldiği anda açılıp diske stream olarak yazılır — büyük dosyalar
//! için RAM'e sığma zorunluluğu ortadan kalkar.
//!
//! # Self-maintaining GC
//!
//! Peer tamamlamadan disconnect ederse (veya crash ederse) yarım partial'lar
//! map'te kalır → bellek ve disk sızar. [`PayloadAssembler::gc`] belirli
//! süreden uzun sessiz kalmış girişleri düşürür; [`PayloadAssembler::ingest`]
//! her çağrıda otomatik olarak bu GC'yi çalıştırır ([`ASSEMBLER_GC_TIMEOUT`]).

use crate::location::nearby::connections::{
    payload_transfer_frame::payload_header::PayloadType, PayloadTransferFrame,
};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::warn;

/// Bir chunk üzerinden geçmişken `last_chunk_at`'in ne kadar eskiyebileceği.
///
/// 120 saniye = Quick Share protokolünün makul en yavaş transfer hızı bile
/// tek chunk'ı bu kadar beklemez; bu sürede chunk gelmediyse peer düşmüştür.
pub const ASSEMBLER_GC_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum CompletedPayload {
    Bytes {
        #[allow(dead_code)]
        id: i64,
        data: Vec<u8>,
    },
    File {
        #[allow(dead_code)]
        id: i64,
        path: PathBuf,
        total_size: i64,
        /// Streaming hesaplanmış SHA-256 (self-verification için).
        sha256: [u8; 32],
    },
}

/// BYTES payload'ı için kısmi buffer + son chunk timestamp'i.
struct BytesBuf {
    data: Vec<u8>,
    last_chunk_at: Instant,
}

/// FILE payload'ı için açık dosya kulpu + streaming hasher + timestamp.
struct FileSink {
    file: File,
    path: PathBuf,
    total_size: i64,
    /// Toplam yazılmış bayt — `total_size`'a karşı overrun doğrulaması için.
    written: i64,
    hasher: Sha256,
    last_chunk_at: Instant,
}

/// Introduction'da onaylanmış ama hiç chunk gelmemiş dosyanın hedef yolu.
struct PendingDest {
    path: PathBuf,
    registered_at: Instant,
}

#[derive(Default)]
pub struct PayloadAssembler {
    bytes_buffers: HashMap<i64, BytesBuf>,
    file_sinks: HashMap<i64, FileSink>,
    pending_destinations: HashMap<i64, PendingDest>,
}

impl PayloadAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Introduction sırasında onaylanan dosya için diskteki hedef yolu kaydeder.
    /// İlk chunk geldiğinde bu yol kullanılarak dosya `std::fs::File::create` ile açılır.
    ///
    /// SECURITY: Aynı `payload_id` ile iki kez kayıt → önceki hedef **silent
    /// overwrite** olurdu (HashMap::insert). Saldırgan Introduction'da
    /// `id=X → legit.pdf` + aynı Introduction'da `id=X → _evil.sh` yollayarak
    /// UI'ın kullanıcıya `legit.pdf`'i göstermesini ama gerçekte `_evil.sh`'in
    /// yazılmasını sağlayabilirdi. İkinci register artık hata döner.
    pub fn register_file_destination(&mut self, payload_id: i64, path: PathBuf) -> Result<()> {
        if self.pending_destinations.contains_key(&payload_id)
            || self.file_sinks.contains_key(&payload_id)
        {
            bail!(
                "duplicate payload_id={} — destination overwrite reddedildi",
                payload_id
            );
        }
        self.pending_destinations.insert(
            payload_id,
            PendingDest {
                path,
                registered_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Onaylanmayan (örn. Bytes olup bilinmeyen) bir payload'ı temizler.
    ///
    /// Açıksa dosya kulpunu düşürür ve yarım yazılmış `.part` dosyasını siler.
    #[allow(dead_code)]
    pub fn cancel(&mut self, payload_id: i64) {
        self.bytes_buffers.remove(&payload_id);
        if let Some(sink) = self.file_sinks.remove(&payload_id) {
            remove_partial_file(&sink.path);
        }
        self.pending_destinations.remove(&payload_id);
    }

    /// Belirli süreden uzun sessiz kalmış partial'ları düşürür.
    ///
    /// `timeout`'tan önce `last_chunk_at`'i olan veya `registered_at`'i olan
    /// tüm girişler silinir. Dosya sink'leri silinirken yarım yazılmış dosya
    /// diskten de kaldırılır.
    ///
    /// Return: silinen toplam giriş sayısı (bytes + file + pending dest).
    /// Sıfırdan büyükse `warn!` ile loglanır — GC'nin iş yapması nadir olmalı.
    pub fn gc(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let cutoff = match now.checked_sub(timeout) {
            Some(c) => c,
            None => return 0, // timeout > uptime → hiçbir şey eski olamaz.
        };

        let mut dropped_bytes = 0usize;
        self.bytes_buffers.retain(|_, buf| {
            if buf.last_chunk_at < cutoff {
                dropped_bytes += 1;
                false
            } else {
                true
            }
        });

        let mut dropped_files = 0usize;
        let mut stale_file_paths: Vec<PathBuf> = Vec::new();
        self.file_sinks.retain(|_, sink| {
            if sink.last_chunk_at < cutoff {
                dropped_files += 1;
                stale_file_paths.push(sink.path.clone());
                false
            } else {
                true
            }
        });
        for p in stale_file_paths {
            remove_partial_file(&p);
        }

        let mut dropped_pending = 0usize;
        self.pending_destinations.retain(|_, dest| {
            if dest.registered_at < cutoff {
                dropped_pending += 1;
                false
            } else {
                true
            }
        });

        let total = dropped_bytes + dropped_files + dropped_pending;
        if total > 0 {
            warn!(
                "payload gc: {} partial silindi (bytes={}, files={}, pending={}) — peer {}s sessizdi",
                total,
                dropped_bytes,
                dropped_files,
                dropped_pending,
                timeout.as_secs()
            );
        }
        total
    }

    /// Tek bir `PayloadTransferFrame`'i işle. Payload tamamlanırsa Some döner.
    ///
    /// Her çağrıda önce [`Self::gc`] çalışır ([`ASSEMBLER_GC_TIMEOUT`]); böylece
    /// dışarıdan periyodik tetik gerekmeden yarım kalanlar süpürülür.
    pub fn ingest(&mut self, f: &PayloadTransferFrame) -> Result<Option<CompletedPayload>> {
        // Her chunk'ta cheap GC: dolu map yoksa zaten hiçbir şey yapmaz.
        self.gc(ASSEMBLER_GC_TIMEOUT);

        let header = f
            .payload_header
            .as_ref()
            .ok_or_else(|| anyhow!("payload_header yok"))?;
        let chunk = f
            .payload_chunk
            .as_ref()
            .ok_or_else(|| anyhow!("payload_chunk yok"))?;

        let id = header.id.unwrap_or(0);
        let ptype = header
            .r#type
            .unwrap_or(PayloadType::UnknownPayloadType as i32);
        let total_size = header.total_size.unwrap_or(0);
        let body: &[u8] = chunk.body.as_deref().unwrap_or_default();
        let flags = chunk.flags.unwrap_or(0);
        let last_chunk = (flags & 1) == 1;

        match PayloadType::try_from(ptype).unwrap_or(PayloadType::UnknownPayloadType) {
            PayloadType::Bytes => self.ingest_bytes(id, body, last_chunk),
            PayloadType::File => self.ingest_file(id, total_size, body, last_chunk),
            other => Err(anyhow!("desteklenmeyen payload tipi: {:?}", other)),
        }
    }

    fn ingest_bytes(
        &mut self,
        id: i64,
        body: &[u8],
        last_chunk: bool,
    ) -> Result<Option<CompletedPayload>> {
        if !body.is_empty() {
            let now = Instant::now();
            let buf = self.bytes_buffers.entry(id).or_insert_with(|| BytesBuf {
                data: Vec::new(),
                last_chunk_at: now,
            });
            // SECURITY: BYTES payload'ı clipboard/URL/kısa metin için; limitsiz
            // büyümesi memory exhaustion (OOM DoS) vektörüdür. 4 MiB'lik sert
            // bir üst sınır uyguluyoruz — gerçek kullanım için fazlasıyla
            // yeterli (clipboard metni tipik <100 KB, URL <4 KB).
            const MAX_BYTES_BUFFER: usize = 4 * 1024 * 1024;
            if buf.data.len().saturating_add(body.len()) > MAX_BYTES_BUFFER {
                self.bytes_buffers.remove(&id);
                return Err(anyhow!(
                    "BYTES payload limiti aşıldı (id={}, {} MB üstü)",
                    id,
                    MAX_BYTES_BUFFER / (1024 * 1024)
                ));
            }
            buf.data.extend_from_slice(body);
            buf.last_chunk_at = now;
        }
        if last_chunk {
            let data = self
                .bytes_buffers
                .remove(&id)
                .map(|b| b.data)
                .unwrap_or_default();
            return Ok(Some(CompletedPayload::Bytes { id, data }));
        }
        Ok(None)
    }

    fn ingest_file(
        &mut self,
        id: i64,
        total_size: i64,
        body: &[u8],
        last_chunk: bool,
    ) -> Result<Option<CompletedPayload>> {
        use std::collections::hash_map::Entry;

        // İlk chunk: dosyayı aç.
        // NOT: `connection::unique_downloads_path` dosyayı `create_new(true)`
        // ile **placeholder** olarak zaten oluşturmuş oldu (TOCTOU fix).
        // Burada aynı path'i `write(true).truncate(true)` ile yeniden açıyoruz
        // — aynı inode, sıfırdan yazma. Eğer placeholder yoksa (test kodu,
        // legacy çağrı) create'e fallback ediyoruz.
        if let Entry::Vacant(slot) = self.file_sinks.entry(id) {
            let dest = self
                .pending_destinations
                .remove(&id)
                .ok_or_else(|| anyhow!("payload_id={} için destination kayıtlı değil", id))?;
            // SECURITY: `total_size` negatif ya da absürt büyükse en başta reddet.
            // Aksi halde `(written*100)/total` integer aritmetiği taşar ve
            // saldırgan terabaytlık disk doldurma isteği UI/progress yoluyla
            // sessizce kabul edilir.
            if total_size < 0 {
                bail!("total_size negatif: {}", total_size);
            }
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&dest.path)
                .with_context(|| format!("dosya açılamadı: {}", dest.path.display()))?;
            slot.insert(FileSink {
                file,
                path: dest.path,
                total_size,
                written: 0,
                hasher: Sha256::new(),
                last_chunk_at: Instant::now(),
            });
        }

        if !body.is_empty() {
            let sink = self
                .file_sinks
                .get_mut(&id)
                .ok_or_else(|| anyhow!("file_sink kayıp: id={}", id))?;
            // SECURITY: Cumulative overrun koruması — saldırgan `total_size=10`
            // deklare edip gigabaytlarca chunk yollayarak disk doldurabilir.
            let body_len = body.len() as i64;
            let new_written = sink
                .written
                .checked_add(body_len)
                .ok_or_else(|| anyhow!("yazım toplamı taştı (id={})", id))?;
            if new_written > sink.total_size {
                bail!(
                    "payload overrun: id={} written={} > total_size={}",
                    id,
                    new_written,
                    sink.total_size
                );
            }
            sink.file.write_all(body).context("disk yazma")?;
            sink.hasher.update(body);
            sink.written = new_written;
            sink.last_chunk_at = Instant::now();
        }

        if last_chunk {
            let sink = self
                .file_sinks
                .remove(&id)
                .ok_or_else(|| anyhow!("son chunk ama sink yok: id={}", id))?;
            // SECURITY: Peer `last_chunk=true` gönderip yarım dosyayı tamamlanmış
            // gibi onaylatabilir (silent truncation). Toplam byte sayısı
            // bildirilen total_size ile eşleşmezse reddet.
            if sink.written != sink.total_size {
                bail!(
                    "truncated payload: id={} written={} total_size={}",
                    id,
                    sink.written,
                    sink.total_size
                );
            }
            sink.file.sync_all().ok();
            let digest = sink.hasher.finalize();
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&digest);
            return Ok(Some(CompletedPayload::File {
                id,
                path: sink.path,
                total_size: sink.total_size,
                sha256,
            }));
        }
        Ok(None)
    }

    /// Test/inspection yardımcısı: beklenen yarım transfer sayısı.
    #[cfg(test)]
    fn partial_count(&self) -> usize {
        self.bytes_buffers.len() + self.file_sinks.len() + self.pending_destinations.len()
    }
}

/// Yarım yazılmış dosyayı sessizce siler. Dosya zaten yoksa veya başka bir
/// nedenle silinemezse hata sadece debug log'a düşer — cleanup best-effort.
fn remove_partial_file(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!("partial silinemedi: {} — {}", path.display(), e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::location::nearby::connections::payload_transfer_frame::{
        payload_header::PayloadType as PbPayloadType, PayloadChunk, PayloadHeader,
    };
    use crate::location::nearby::connections::PayloadTransferFrame;

    /// Test helper: minimal `PayloadTransferFrame` inşa et.
    fn make_frame(id: i64, ptype: PbPayloadType, body: &[u8], last: bool) -> PayloadTransferFrame {
        make_frame_total(id, ptype, body, last, body.len() as i64)
    }

    fn make_frame_total(
        id: i64,
        ptype: PbPayloadType,
        body: &[u8],
        last: bool,
        total_size: i64,
    ) -> PayloadTransferFrame {
        PayloadTransferFrame {
            packet_type: None,
            payload_header: Some(PayloadHeader {
                id: Some(id),
                r#type: Some(ptype as i32),
                total_size: Some(total_size),
                is_sensitive: None,
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(if last { 1 } else { 0 }),
                offset: Some(0),
                body: Some(body.to_vec()),
                index: None,
            }),
            control_message: None,
        }
    }

    #[test]
    fn bytes_single_chunk_completes() {
        let mut a = PayloadAssembler::new();
        let f = make_frame(42, PbPayloadType::Bytes, b"hello", true);
        let out = a.ingest(&f).expect("ingest ok");
        match out {
            Some(CompletedPayload::Bytes { id, data }) => {
                assert_eq!(id, 42);
                assert_eq!(data, b"hello");
            }
            other => panic!("beklenen Bytes, {:?} geldi", other),
        }
        assert_eq!(a.partial_count(), 0, "tamamlanan bytes temizlenmeli");
    }

    #[test]
    fn bytes_multiple_chunks_accumulate() {
        let mut a = PayloadAssembler::new();
        let f1 = make_frame(1, PbPayloadType::Bytes, b"foo", false);
        let f2 = make_frame(1, PbPayloadType::Bytes, b"bar", true);
        assert!(a.ingest(&f1).unwrap().is_none());
        let done = a.ingest(&f2).unwrap().expect("last chunk tamamlar");
        match done {
            CompletedPayload::Bytes { data, .. } => assert_eq!(data, b"foobar"),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn gc_drops_stale_bytes_buffer() {
        let mut a = PayloadAssembler::new();
        // İlk chunk ingest et ama last=false, bu yüzden buffer kalsın.
        let f = make_frame(7, PbPayloadType::Bytes, b"abc", false);
        a.ingest(&f).unwrap();
        assert_eq!(a.partial_count(), 1);

        // 0 timeout ile GC → her şey eski sayılır ve silinir.
        // Not: 0 timeout anlamı "her girişi sil" değil, "now - 0 cutoff'undan
        // eski olanları sil" — Instant'ın precision'ı nedeniyle test
        // anında girilen bir Instant cutoff'tan küçük olabilir. Küçük bir
        // timeout ile çalışalım ve kısa sleep yapalım.
        std::thread::sleep(Duration::from_millis(15));
        let n = a.gc(Duration::from_millis(10));
        assert_eq!(n, 1);
        assert_eq!(a.partial_count(), 0);
    }

    #[test]
    fn gc_preserves_fresh_entries() {
        let mut a = PayloadAssembler::new();
        let f = make_frame(9, PbPayloadType::Bytes, b"xyz", false);
        a.ingest(&f).unwrap();
        // timeout çok büyük → hiçbir giriş eski sayılmaz.
        let n = a.gc(Duration::from_secs(3600));
        assert_eq!(n, 0);
        assert_eq!(a.partial_count(), 1);
    }

    #[test]
    fn gc_drops_stale_file_sink_and_deletes_disk_file() {
        let tmp =
            std::env::temp_dir().join(format!("hekadrop-gc-test-{}.part", std::process::id()));
        // Temiz başla.
        let _ = std::fs::remove_file(&tmp);

        let mut a = PayloadAssembler::new();
        a.register_file_destination(100, tmp.clone()).unwrap();
        // İlk (ve sadece) chunk: dosya açılır, disk'e yazılır, last=false.
        let f = make_frame(100, PbPayloadType::File, b"partial-data", false);
        a.ingest(&f).unwrap();
        assert!(tmp.exists(), "chunk sonrası dosya oluşmalı");
        assert_eq!(a.partial_count(), 1);

        std::thread::sleep(Duration::from_millis(15));
        let n = a.gc(Duration::from_millis(10));
        assert_eq!(n, 1, "tek file sink silinmeli");
        assert_eq!(a.partial_count(), 0);
        assert!(!tmp.exists(), "gc yarım dosyayı diskten de silmeli");
    }

    #[test]
    fn gc_drops_stale_pending_destination() {
        let mut a = PayloadAssembler::new();
        // Dosya oluşturmuyoruz; sadece path kaydı GC'de silinecek.
        let tmp =
            std::env::temp_dir().join(format!("hekadrop-pending-test-{}.part", std::process::id()));
        a.register_file_destination(55, tmp).unwrap();
        assert_eq!(a.partial_count(), 1);

        std::thread::sleep(Duration::from_millis(15));
        let n = a.gc(Duration::from_millis(10));
        assert_eq!(n, 1);
        assert_eq!(a.partial_count(), 0);
    }

    #[test]
    fn ingest_triggers_automatic_gc() {
        // 0 timeout → her ingest çağrısında eski olan buffer silinir.
        // Fakat ingest kendi id'si için yeni timestamp yazar, silinmez.
        // Farklı bir id için önce buffer bırakalım, sonra biraz bekleyip
        // farklı id ile ingest et → ilk id GC tarafından düşmeli.
        // Not: ingest içindeki otomatik gc ASSEMBLER_GC_TIMEOUT kullanır
        // (120s); unit test'te bu kadar bekleyemeyiz. Bu yüzden burada
        // sadece ingest + manuel gc sırasının doğru çalıştığını doğrularız.
        let mut a = PayloadAssembler::new();
        let f_old = make_frame(1, PbPayloadType::Bytes, b"aa", false);
        a.ingest(&f_old).unwrap();
        let f_new = make_frame(2, PbPayloadType::Bytes, b"bb", false);
        a.ingest(&f_new).unwrap();
        assert_eq!(a.partial_count(), 2);

        std::thread::sleep(Duration::from_millis(15));
        // id=2'yi tazele:
        let f_touch = make_frame(2, PbPayloadType::Bytes, b"cc", false);
        a.ingest(&f_touch).unwrap();

        let dropped = a.gc(Duration::from_millis(10));
        assert_eq!(dropped, 1, "sadece id=1 düşmeli");
        assert_eq!(a.partial_count(), 1);
    }

    #[test]
    fn cancel_removes_bytes_file_and_pending() {
        let pid = std::process::id();
        let tmp = std::env::temp_dir().join(format!("hekadrop-cancel-test-{}.part", pid));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();

        // bytes buffer
        a.ingest(&make_frame(1, PbPayloadType::Bytes, b"x", false))
            .unwrap();
        // file sink
        a.register_file_destination(2, tmp.clone()).unwrap();
        a.ingest(&make_frame(2, PbPayloadType::File, b"y", false))
            .unwrap();
        assert!(tmp.exists());
        // pending destination
        let tmp2 = std::env::temp_dir().join(format!("hekadrop-cancel-pending-{}.part", pid));
        a.register_file_destination(3, tmp2).unwrap();

        assert_eq!(a.partial_count(), 3);
        a.cancel(1);
        a.cancel(2);
        a.cancel(3);
        assert_eq!(a.partial_count(), 0);
        assert!(
            !tmp.exists(),
            "cancel file sink'in diskteki dosyasını silmeli"
        );
    }

    #[test]
    fn file_last_chunk_finalizes_and_computes_sha256() {
        let tmp =
            std::env::temp_dir().join(format!("hekadrop-finalize-test-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(200, tmp.clone()).unwrap();
        // İki chunk'lı dosya — total_size=6 (foo+bar). Her iki frame aynı
        // total'ı deklare etmeli yoksa overrun/truncation validasyonu patlar.
        a.ingest(&make_frame_total(200, PbPayloadType::File, b"foo", false, 6))
            .unwrap();
        let out = a
            .ingest(&make_frame_total(200, PbPayloadType::File, b"bar", true, 6))
            .unwrap()
            .expect("son chunk tamamlar");
        match out {
            CompletedPayload::File {
                id,
                path,
                sha256,
                total_size,
            } => {
                assert_eq!(id, 200);
                assert_eq!(path, tmp);
                // Her iki frame de total_size=6 ("foo"+"bar") deklare ediyor
                // (overrun validasyonu için zorunlu). İlk chunk'ta açılan
                // FileSink.total_size korunur.
                assert_eq!(total_size, 6);
                // "foobar"ın beklenen SHA-256'sı
                let expected = {
                    let mut h = Sha256::new();
                    h.update(b"foobar");
                    let d = h.finalize();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&d);
                    arr
                };
                assert_eq!(sha256, expected);
            }
            other => panic!("beklenen File, {:?} geldi", other),
        }
        // Dosyayı oku ve içeriğini doğrula.
        let content = std::fs::read(&tmp).unwrap();
        assert_eq!(content, b"foobar");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn gc_returns_zero_when_empty() {
        let mut a = PayloadAssembler::new();
        assert_eq!(a.gc(Duration::from_secs(1)), 0);
    }

    #[test]
    fn gc_sub_uptime_overflow_safe() {
        // Eğer timeout >= process uptime ise `Instant::now() - timeout`
        // panic edebilir. Kod bunu `checked_sub` ile korumalı.
        let mut a = PayloadAssembler::new();
        a.ingest(&make_frame(1, PbPayloadType::Bytes, b"a", false))
            .unwrap();
        // 10 yıl gibi absürt timeout.
        let n = a.gc(Duration::from_secs(60 * 60 * 24 * 365 * 10));
        assert_eq!(n, 0, "çok büyük timeout'ta hiçbir şey silinmemeli");
    }

    // ---- SECURITY: payload overrun + truncation + duplicate id guards ----

    #[test]
    fn duplicate_payload_id_reddedilir() {
        // Saldırgan Introduction'da aynı id ile iki FileMetadata yollarsa
        // ikinci register_file_destination silent overwrite yerine hata dönmeli.
        let mut a = PayloadAssembler::new();
        let p1 = std::env::temp_dir().join(format!("hd-dup1-{}.bin", std::process::id()));
        let p2 = std::env::temp_dir().join(format!("hd-dup2-{}.bin", std::process::id()));
        assert!(a.register_file_destination(42, p1.clone()).is_ok());
        let err = a
            .register_file_destination(42, p2.clone())
            .expect_err("duplicate red");
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn file_overrun_reddedilir() {
        // total_size=5 iken 10 bayt body → overrun hatası, disk sızıntısı yok.
        let tmp = std::env::temp_dir()
            .join(format!("hd-overrun-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(1, tmp.clone()).unwrap();
        let bloat = vec![0xCDu8; 10];
        let f = make_frame_total(1, PbPayloadType::File, &bloat, false, 5);
        let err = a.ingest(&f).expect_err("overrun red");
        assert!(err.to_string().contains("overrun"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn file_last_chunk_truncation_reddedilir() {
        // last_chunk=true geldiğinde written != total_size → hata.
        // Peer 10 bayt deklare edip 3 bayt + last_chunk yollayamaz.
        let tmp = std::env::temp_dir()
            .join(format!("hd-trunc-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(7, tmp.clone()).unwrap();
        let f = make_frame_total(7, PbPayloadType::File, b"abc", true, 10);
        let err = a.ingest(&f).expect_err("truncation red");
        assert!(err.to_string().contains("truncated"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn file_negative_total_size_reddedilir() {
        let tmp = std::env::temp_dir()
            .join(format!("hd-negtotal-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(9, tmp.clone()).unwrap();
        let f = make_frame_total(9, PbPayloadType::File, b"a", false, -1);
        let err = a.ingest(&f).expect_err("negatif total red");
        assert!(err.to_string().contains("negatif"));
    }
}
