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

use crate::error::HekaError;
use anyhow::{anyhow, Context, Result};
use hekadrop_proto::location::nearby::connections::{
    payload_transfer_frame::payload_header::PayloadType, PayloadTransferFrame,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::warn;

/// BufWriter iç tampon boyutu. 128 KiB, Quick Share'in 512 KiB chunk'ları için
/// ~4 chunk'lık tampon sağlar; syscall sayısını düşürürken RAM maliyeti düşük.
/// Performans raporu 100 Mbps'de tokio::fs async write per-chunk ~5-10 µs
/// syscall + wakeup overhead rapor etti; sync std::io + BufWriter bunu eler.
const FILE_WRITE_BUF_CAPACITY: usize = 128 * 1024;

/// Sync bir closure'ı runtime flavor'una göre çalıştırır:
/// - **MultiThread runtime** (prod, `#[tokio::test(flavor = "multi_thread")]`):
///   [`tokio::task::block_in_place`] sinyaliyle sar — tokio bu worker'ı
///   "blocking" olarak işaretler, park halindeki async task'ları başka
///   worker'a taşır. Böylece yavaş disk (iCloud Drive, SMB/NFS mount,
///   yavaş USB) syscall'ları network read / UI task'ları geciktirmez.
/// - **CurrentThread runtime** (default `#[tokio::test]`): `block_in_place`
///   çağrısı panik atar; closure'ı direkt çağırırız. Tek worker'ı zaten
///   tutuyoruz, kaybedecek diğer worker yok.
/// - **Runtime yok** (senkron çağrı path'i): direkt çağır.
#[inline]
fn block_in_place_if_multi<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

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
///
/// Disk I/O **senkron** (`std::fs::File` + `std::io::BufWriter`). Async
/// (`tokio::fs`) sürümü chunk başına ~5-10 µs tokio task-pool + syscall
/// overhead getiriyordu; 512 KiB chunk'lar zaten kısa süreli blocking I/O'ya
/// izin verir ve 128 KiB BufWriter tamponu syscall sayısını azaltır.
/// Sync I/O çağrıları `ingest_file` içinde [`block_in_place_if_multi`] ile
/// sarılır — multi-thread runtime'da tokio'ya "blocking" sinyali verilir ki
/// yavaş disk (iCloud Drive, SMB/NFS, yavaş USB) runtime worker'ını tutmasın;
/// current_thread runtime'da (unit test) `block_in_place` panik edeceği için
/// sync çağrı direkt yapılır.
struct FileSink {
    writer: BufWriter<File>,
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
            return Err(HekaError::DuplicatePayloadId(payload_id).into());
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
    /// Hiç chunk gelmemiş pending destination kayıtları için de diskteki
    /// 0-bayt placeholder'ı siler — aksi halde iptal sonrası indirme
    /// klasöründe sahibsiz sıfır bayt dosyalar birikir (review-18 MED).
    #[allow(dead_code)]
    pub fn cancel(&mut self, payload_id: i64) {
        self.bytes_buffers.remove(&payload_id);
        if let Some(sink) = self.file_sinks.remove(&payload_id) {
            remove_partial_file(&sink.path);
        }
        if let Some(dest) = self.pending_destinations.remove(&payload_id) {
            remove_partial_file(&dest.path);
        }
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
        // timeout > uptime → hiçbir şey eski olamaz, GC iptal.
        let Some(cutoff) = now.checked_sub(timeout) else {
            return 0;
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
    pub async fn ingest(&mut self, f: &PayloadTransferFrame) -> Result<Option<CompletedPayload>> {
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
            PayloadType::File => self.ingest_file(id, total_size, body, last_chunk).await,
            other => Err(HekaError::ProtocolState(format!(
                "desteklenmeyen payload tipi: {:?}",
                other
            ))
            .into()),
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
                return Err(HekaError::PayloadIo(format!(
                    "BYTES payload limiti aşıldı (id={}, {} MB üstü)",
                    id,
                    MAX_BYTES_BUFFER / (1024 * 1024)
                ))
                .into());
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

    async fn ingest_file(
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
                return Err(HekaError::PayloadSizeNegative(total_size).into());
            }
            // Quick Share pratikte 1 TiB'den büyük tek dosya göndermez —
            // 1 TiB üstü değer neredeyse kesin kötü niyetli / broken peer.
            // Bu sınırı koymadan `(written*100)/total` progress aritmetiği ve
            // `i64 → u64` cast'lerde sürpriz davranışlara yol açar.
            const MAX_FILE_BYTES: i64 = 1 << 40; // 1 TiB
            if total_size > MAX_FILE_BYTES {
                return Err(HekaError::PayloadSizeAbsurd(total_size).into());
            }
            // SECURITY: Hedef yol symlink ise saldırgan (veya TOCTOU race ile
            // üçüncü taraf) placeholder'ı symlink'e çevirip bizi keyfi dosyaya
            // yazmaya zorlayabilir. `symlink_metadata` link'i resolve etmez;
            // symlink tespit edersek işlemi iptal ederiz.
            // NOT: Placeholder'ın olmaması yasal bir durum (test/legacy kod
            // `register_file_destination`'ı bir path ile çağırıp diske
            // placeholder yaratmadan `ingest` çağırabilir — `create:true`
            // fallback'i bu yol için mevcut). Bu yüzden NotFound'u tolere et.
            match std::fs::symlink_metadata(&dest.path) {
                Ok(md) => {
                    if md.file_type().is_symlink() {
                        return Err(
                            HekaError::SymlinkTarget(dest.path.display().to_string()).into()
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Placeholder yok → legacy/test kodu; `create:true` aşağıda yaratacak.
                }
                Err(e) => {
                    return Err(anyhow::Error::from(e)).with_context(|| {
                        format!("hedef metadata okunamadı: {}", dest.path.display())
                    });
                }
            }
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&dest.path)
                .with_context(|| format!("dosya açılamadı: {}", dest.path.display()))?;
            let writer = BufWriter::with_capacity(FILE_WRITE_BUF_CAPACITY, file);
            slot.insert(FileSink {
                writer,
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
            // usize → i64: pratikte body 4 MiB ile sınırlı (CHUNK_SIZE),
            // i64::MAX'e ulaşmak imkânsız ama saldırgan-controlled length
            // değerini try_from ile defensive sınırlıyoruz. Orijinal
            // `TryFromIntError` mesaja eklenir.
            let body_len = i64::try_from(body.len()).map_err(|e| {
                HekaError::PayloadIo(format!("chunk body i64'a sığmıyor (id={id}): {e}"))
            })?;
            let new_written = sink
                .written
                .checked_add(body_len)
                .ok_or_else(|| HekaError::PayloadIo(format!("yazım toplamı taştı (id={})", id)))?;
            if new_written > sink.total_size {
                return Err(HekaError::PayloadOverrun {
                    id,
                    written: new_written,
                    total: sink.total_size,
                }
                .into());
            }
            // Sync I/O'yu multi-thread runtime'da tokio'ya "blocking" olarak
            // işaretle — iCloud Drive / SMB / yavaş USB'de write_all 10-100 ms
            // bloklayabilir; bu sırada diğer async task'lar başka worker'a
            // taşınsın. Current-thread runtime'da (unit test) fallback: direkt
            // çağrı — block_in_place current_thread'de panik eder.
            block_in_place_if_multi(|| sink.writer.write_all(body)).context("disk yazma")?;
            sink.hasher.update(body);
            sink.written = new_written;
            sink.last_chunk_at = Instant::now();
        }

        if last_chunk {
            let mut sink = self
                .file_sinks
                .remove(&id)
                .ok_or_else(|| anyhow!("son chunk ama sink yok: id={}", id))?;
            // SECURITY: Peer `last_chunk=true` gönderip yarım dosyayı tamamlanmış
            // gibi onaylatabilir (silent truncation). Toplam byte sayısı
            // bildirilen total_size ile eşleşmezse reddet.
            if sink.written != sink.total_size {
                return Err(HekaError::PayloadTruncated {
                    id,
                    written: sink.written,
                    total: sink.total_size,
                }
                .into());
            }
            // BufWriter drop'ta flush'u sessizce yutar — kritik finalize'da
            // explicit flush + sync_all çağırıp hataları propagate et.
            // Durability: sync_all hatası yutulursa peer'a başarı mesajı
            // gönderebiliriz ama disk'te veri henüz yok → crash durumunda
            // dosya boş/yarım kalır. Hatayı propagate et ki user retry'la
            // anlamlı bir sonuç alabilsin.
            //
            // flush + sync_all tek blokta: ikisi de blocking syscall
            // (fsync özellikle yavaş disklerde 100+ ms olabilir) — iki ayrı
            // block_in_place yerine tek sinyalle tokio'ya yük bildir.
            let flush_sync_res: std::io::Result<()> = block_in_place_if_multi(|| {
                sink.writer.flush()?;
                sink.writer.get_ref().sync_all()?;
                Ok(())
            });
            flush_sync_res.with_context(|| {
                format!(
                    "dosya finalize edilemedi (flush/fsync): id={} path={}",
                    id,
                    sink.path.display()
                )
            })?;
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
            tracing::debug!(
                "partial silinemedi: {} — {}",
                crate::log_redact::path_basename(path),
                e
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_wrap)]
mod tests {
    use super::*;
    use hekadrop_proto::location::nearby::connections::payload_transfer_frame::{
        payload_header::PayloadType as PbPayloadType, PayloadChunk, PayloadHeader,
    };
    use hekadrop_proto::location::nearby::connections::PayloadTransferFrame;

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
                body: Some(body.to_vec().into()),
                index: None,
            }),
            control_message: None,
        }
    }

    #[tokio::test]
    async fn bytes_single_chunk_completes() {
        let mut a = PayloadAssembler::new();
        let f = make_frame(42, PbPayloadType::Bytes, b"hello", true);
        let out = a.ingest(&f).await.expect("ingest ok");
        match out {
            Some(CompletedPayload::Bytes { id, data }) => {
                assert_eq!(id, 42);
                assert_eq!(data, b"hello");
            }
            other => panic!("beklenen Bytes, {:?} geldi", other),
        }
        assert_eq!(a.partial_count(), 0, "tamamlanan bytes temizlenmeli");
    }

    #[tokio::test]
    async fn bytes_multiple_chunks_accumulate() {
        let mut a = PayloadAssembler::new();
        let f1 = make_frame(1, PbPayloadType::Bytes, b"foo", false);
        let f2 = make_frame(1, PbPayloadType::Bytes, b"bar", true);
        assert!(a.ingest(&f1).await.unwrap().is_none());
        let done = a.ingest(&f2).await.unwrap().expect("last chunk tamamlar");
        match done {
            CompletedPayload::Bytes { data, .. } => assert_eq!(data, b"foobar"),
            other => panic!("{:?}", other),
        }
    }

    #[tokio::test]
    async fn gc_drops_stale_bytes_buffer() {
        let mut a = PayloadAssembler::new();
        // İlk chunk ingest et ama last=false, bu yüzden buffer kalsın.
        let f = make_frame(7, PbPayloadType::Bytes, b"abc", false);
        a.ingest(&f).await.unwrap();
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

    #[tokio::test]
    async fn gc_preserves_fresh_entries() {
        let mut a = PayloadAssembler::new();
        let f = make_frame(9, PbPayloadType::Bytes, b"xyz", false);
        a.ingest(&f).await.unwrap();
        // timeout çok büyük → hiçbir giriş eski sayılmaz.
        let n = a.gc(Duration::from_secs(3600));
        assert_eq!(n, 0);
        assert_eq!(a.partial_count(), 1);
    }

    #[tokio::test]
    async fn gc_drops_stale_file_sink_and_deletes_disk_file() {
        let tmp =
            std::env::temp_dir().join(format!("hekadrop-gc-test-{}.part", std::process::id()));
        // Temiz başla.
        let _ = std::fs::remove_file(&tmp);

        let mut a = PayloadAssembler::new();
        a.register_file_destination(100, tmp.clone()).unwrap();
        // İlk (ve sadece) chunk: dosya açılır, disk'e yazılır, last=false.
        let f = make_frame(100, PbPayloadType::File, b"partial-data", false);
        a.ingest(&f).await.unwrap();
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

    #[tokio::test]
    async fn ingest_triggers_automatic_gc() {
        // 0 timeout → her ingest çağrısında eski olan buffer silinir.
        // Fakat ingest kendi id'si için yeni timestamp yazar, silinmez.
        // Farklı bir id için önce buffer bırakalım, sonra biraz bekleyip
        // farklı id ile ingest et → ilk id GC tarafından düşmeli.
        // Not: ingest içindeki otomatik gc ASSEMBLER_GC_TIMEOUT kullanır
        // (120s); unit test'te bu kadar bekleyemeyiz. Bu yüzden burada
        // sadece ingest + manuel gc sırasının doğru çalıştığını doğrularız.
        let mut a = PayloadAssembler::new();
        let f_old = make_frame(1, PbPayloadType::Bytes, b"aa", false);
        a.ingest(&f_old).await.unwrap();
        let f_new = make_frame(2, PbPayloadType::Bytes, b"bb", false);
        a.ingest(&f_new).await.unwrap();
        assert_eq!(a.partial_count(), 2);

        std::thread::sleep(Duration::from_millis(15));
        // id=2'yi tazele:
        let f_touch = make_frame(2, PbPayloadType::Bytes, b"cc", false);
        a.ingest(&f_touch).await.unwrap();

        let dropped = a.gc(Duration::from_millis(10));
        assert_eq!(dropped, 1, "sadece id=1 düşmeli");
        assert_eq!(a.partial_count(), 1);
    }

    #[tokio::test]
    async fn cancel_removes_bytes_file_and_pending() {
        let pid = std::process::id();
        let rnd: u32 = rand::random();
        let tmp = std::env::temp_dir().join(format!("hekadrop-cancel-test-{}-{}.part", pid, rnd));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();

        // bytes buffer
        a.ingest(&make_frame(1, PbPayloadType::Bytes, b"x", false))
            .await
            .unwrap();
        // file sink (total_size=big enough for one-byte body)
        a.register_file_destination(2, tmp.clone()).unwrap();
        a.ingest(&make_frame_total(2, PbPayloadType::File, b"y", false, 10))
            .await
            .unwrap();
        assert!(tmp.exists());
        // pending destination — review-18 MED: cancel artık placeholder'ı da silmeli.
        let tmp2 =
            std::env::temp_dir().join(format!("hekadrop-cancel-pending-{}-{}.part", pid, rnd));
        // Diskte sıfır bayt placeholder simulate et (unique_downloads_path davranışı).
        std::fs::write(&tmp2, b"").expect("placeholder yarat");
        a.register_file_destination(3, tmp2.clone()).unwrap();

        assert_eq!(a.partial_count(), 3);
        a.cancel(1);
        a.cancel(2);
        a.cancel(3);
        assert_eq!(a.partial_count(), 0);
        assert!(
            !tmp.exists(),
            "cancel file sink'in diskteki dosyasını silmeli"
        );
        assert!(
            !tmp2.exists(),
            "cancel pending destination placeholder'ını diskten silmeli"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn ingest_file_symlink_destination_reddeder() {
        // review-18: dest.path symlink'e dönüştüyse (TOCTOU) ingest_file
        // reddetmelidir.
        let pid = std::process::id();
        let rnd: u32 = rand::random();
        let real = std::env::temp_dir().join(format!("hekadrop-symlink-real-{}-{}.bin", pid, rnd));
        let link = std::env::temp_dir().join(format!("hekadrop-symlink-link-{}-{}.bin", pid, rnd));
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::write(&real, b"").expect("real yarat");
        std::os::unix::fs::symlink(&real, &link).expect("symlink yarat");

        let mut a = PayloadAssembler::new();
        a.register_file_destination(42, link.clone()).unwrap();
        let err = a
            .ingest(&make_frame_total(42, PbPayloadType::File, b"y", false, 10))
            .await
            .expect_err("symlink hedef reddedilmeli");
        assert!(
            err.to_string().contains("symlink"),
            "hata mesajı symlink belirtmeli, aldı: {}",
            err
        );

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&real);
    }

    #[tokio::test]
    async fn ingest_file_total_size_absurd_buyuk_reddeder() {
        // review-18: 1 TiB üstü bildirilen dosya başlamadan reddedilmeli.
        let pid = std::process::id();
        let rnd: u32 = rand::random();
        let tmp = std::env::temp_dir().join(format!("hekadrop-absurd-{}-{}.bin", pid, rnd));
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"").expect("placeholder");

        let mut a = PayloadAssembler::new();
        a.register_file_destination(42, tmp.clone()).unwrap();
        let absurd = (1i64 << 40) + 1; // 1 TiB + 1
        let err = a
            .ingest(&make_frame_total(
                42,
                PbPayloadType::File,
                b"x",
                false,
                absurd,
            ))
            .await
            .expect_err("absurd total_size reddedilmeli");
        assert!(
            err.to_string().contains("absürt") || err.to_string().contains("1 TiB"),
            "hata mesajı limit belirtmeli, aldı: {}",
            err
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn file_last_chunk_finalizes_and_computes_sha256() {
        let tmp =
            std::env::temp_dir().join(format!("hekadrop-finalize-test-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(200, tmp.clone()).unwrap();
        // İki chunk'lı dosya — total_size=6 (foo+bar). Her iki frame aynı
        // total'ı deklare etmeli yoksa overrun/truncation validasyonu patlar.
        a.ingest(&make_frame_total(
            200,
            PbPayloadType::File,
            b"foo",
            false,
            6,
        ))
        .await
        .unwrap();
        let out = a
            .ingest(&make_frame_total(200, PbPayloadType::File, b"bar", true, 6))
            .await
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

    #[tokio::test]
    async fn gc_sub_uptime_overflow_safe() {
        // Eğer timeout >= process uptime ise `Instant::now() - timeout`
        // panic edebilir. Kod bunu `checked_sub` ile korumalı.
        let mut a = PayloadAssembler::new();
        a.ingest(&make_frame(1, PbPayloadType::Bytes, b"a", false))
            .await
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

    #[tokio::test]
    async fn file_overrun_reddedilir() {
        // total_size=5 iken 10 bayt body → overrun hatası, disk sızıntısı yok.
        let tmp = std::env::temp_dir().join(format!("hd-overrun-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(1, tmp.clone()).unwrap();
        let bloat = vec![0xCDu8; 10];
        let f = make_frame_total(1, PbPayloadType::File, &bloat, false, 5);
        let err = a.ingest(&f).await.expect_err("overrun red");
        assert!(err.to_string().contains("overrun"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn file_last_chunk_truncation_reddedilir() {
        // last_chunk=true geldiğinde written != total_size → hata.
        // Peer 10 bayt deklare edip 3 bayt + last_chunk yollayamaz.
        let tmp = std::env::temp_dir().join(format!("hd-trunc-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(7, tmp.clone()).unwrap();
        let f = make_frame_total(7, PbPayloadType::File, b"abc", true, 10);
        let err = a.ingest(&f).await.expect_err("truncation red");
        assert!(err.to_string().contains("truncated"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn file_negative_total_size_reddedilir() {
        let tmp = std::env::temp_dir().join(format!("hd-negtotal-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut a = PayloadAssembler::new();
        a.register_file_destination(9, tmp.clone()).unwrap();
        let f = make_frame_total(9, PbPayloadType::File, b"a", false, -1);
        let err = a.ingest(&f).await.expect_err("negatif total red");
        assert!(err.to_string().contains("negatif"));
    }
}
