//! Payload reassembly — `PayloadTransferFrame` chunk'larını toplar.
//!
//! BYTES tipindeki küçük payload'lar (sharing frame'ler) bellekte birikir.
//! FILE tipindeki payload'lar, Introduction sırasında belirlenen yola
//! ilk chunk geldiği anda açılıp diske stream olarak yazılır — büyük dosyalar
//! için RAM'e sığma zorunluluğu ortadan kalkar.

use crate::location::nearby::connections::{
    payload_transfer_frame::payload_header::PayloadType, PayloadTransferFrame,
};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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
    },
}

struct FileSink {
    file: File,
    path: PathBuf,
    total_size: i64,
    written: i64,
}

#[derive(Default)]
pub struct PayloadAssembler {
    bytes_buffers: HashMap<i64, Vec<u8>>,
    file_sinks: HashMap<i64, FileSink>,
    pending_destinations: HashMap<i64, PathBuf>,
}

impl PayloadAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Introduction sırasında onaylanan dosya için diskteki hedef yolu kaydeder.
    /// İlk chunk geldiğinde bu yol kullanılarak dosya `std::fs::File::create` ile açılır.
    pub fn register_file_destination(&mut self, payload_id: i64, path: PathBuf) {
        self.pending_destinations.insert(payload_id, path);
    }

    /// Onaylanmayan (örn. Bytes olup bilinmeyen) bir payload'ı temizler.
    #[allow(dead_code)]
    pub fn cancel(&mut self, payload_id: i64) {
        self.bytes_buffers.remove(&payload_id);
        if let Some(sink) = self.file_sinks.remove(&payload_id) {
            let _ = std::fs::remove_file(&sink.path);
        }
        self.pending_destinations.remove(&payload_id);
    }

    /// Tek bir `PayloadTransferFrame`'i işle. Payload tamamlanırsa Some döner.
    pub fn ingest(&mut self, f: &PayloadTransferFrame) -> Result<Option<CompletedPayload>> {
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
            self.bytes_buffers
                .entry(id)
                .or_default()
                .extend_from_slice(body);
        }
        if last_chunk {
            let data = self.bytes_buffers.remove(&id).unwrap_or_default();
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
        // İlk chunk: dosyayı aç.
        if !self.file_sinks.contains_key(&id) {
            let path = self
                .pending_destinations
                .remove(&id)
                .ok_or_else(|| anyhow!("payload_id={} için destination kayıtlı değil", id))?;
            let file = File::create(&path)
                .with_context(|| format!("dosya oluşturulamadı: {}", path.display()))?;
            self.file_sinks.insert(
                id,
                FileSink {
                    file,
                    path,
                    total_size,
                    written: 0,
                },
            );
        }

        if !body.is_empty() {
            let sink = self
                .file_sinks
                .get_mut(&id)
                .ok_or_else(|| anyhow!("file_sink kayıp: id={}", id))?;
            sink.file.write_all(body).context("disk yazma")?;
            sink.written += body.len() as i64;
        }

        if last_chunk {
            let sink = self
                .file_sinks
                .remove(&id)
                .ok_or_else(|| anyhow!("son chunk ama sink yok: id={}", id))?;
            sink.file.sync_all().ok();
            return Ok(Some(CompletedPayload::File {
                id,
                path: sink.path,
                total_size: sink.total_size,
            }));
        }
        Ok(None)
    }
}
