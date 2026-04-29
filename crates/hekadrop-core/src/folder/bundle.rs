//! RFC-0005 §2 — `HEKABUND` v1 wire-byte container.
//!
//! Stateless encoder/decoder primitives. Sender bu modülü `BundleWriter` ile
//! header + manifest + chunked body bytes üretmek için kullanır; receiver
//! `BundleReader` ile temp `.bundle` file'ını parse + trailer verify eder.
//!
//! Bu modül **disk I/O policy'si tanımlamaz** — `BundleWriter` saf hash chain
//! ile header/trailer encoder işidir; caller (sender pipeline) byte'ları
//! nereye yazacağını seçer (TCP socket veya `FileSink`). `BundleReader`
//! `std::fs::File` üzerinden çalışır çünkü receiver per-file extract için
//! seek/random read ihtiyacı duyar.
//!
//! Wire layout (`docs/protocol/folder-payload.md` §2):
//! ```text
//! offset           size       field
//! ---------------  ---------  -------------------
//! 0                8          magic = b"HEKABUND"
//! 8                4          version (BE u32; v1 = 1)
//! 12               4          manifest_len (BE u32; ≤ 8 MiB)
//! 16               N          manifest_json (UTF-8)
//! 16+N             M          concat_data
//! 16+N+M           32         trailer_sha256
//! ```

use crate::folder::manifest::ManifestError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use subtle::ConstantTimeEq;

/// `HEKABUND` magic — bundle'ın ilk 8 byte'ı (ASCII).
pub const HEKABUND_MAGIC: [u8; 8] = *b"HEKABUND";

/// `HEKABUND` v1 wire sürümü (BE u32).
pub const HEKABUND_VERSION: u32 = 1;

/// Trailer SHA-256 uzunluğu (sabit).
pub const TRAILER_LEN: usize = 32;

/// `manifest_len` üst sınırı: 8 MiB (`docs/.../folder-payload.md` §2.3).
pub const MAX_MANIFEST_LEN: u32 = 8 * 1024 * 1024;

/// Header uzunluğu: magic (8) + version (4) + `manifest_len` (4) = 16 byte.
pub const HEADER_LEN: usize = 8 + 4 + 4;

/// `HEKABUND` header — 16 byte sabit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleHeader {
    /// Wire sürümü; v1 boyunca `HEKABUND_VERSION` (== 1).
    pub version: u32,
    /// Manifest JSON byte uzunluğu (≤ `MAX_MANIFEST_LEN`).
    pub manifest_len: u32,
}

impl BundleHeader {
    /// Header'ı 16-byte fixed-size buffer'a encode et (magic + version BE +
    /// `manifest_len` BE).
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&HEKABUND_MAGIC);
        out[8..12].copy_from_slice(&self.version.to_be_bytes());
        out[12..16].copy_from_slice(&self.manifest_len.to_be_bytes());
        out
    }

    /// Header'ı slice'tan parse et — magic gate, version check, `manifest_len`
    /// cap.
    ///
    /// Sıra (`docs/.../folder-payload.md` §2.2 / §2.3):
    /// 1. uzunluk en az `HEADER_LEN`
    /// 2. magic `HEKABUND`
    /// 3. `version == HEKABUND_VERSION`
    /// 4. `manifest_len ≤ MAX_MANIFEST_LEN` (denial-of-service guard)
    /// 5. `manifest_len > 0` (en az `version` + `root_name` + `total_entries`
    ///    + `entries`)
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.len() < HEADER_LEN {
            return Err(BundleError::HeaderTooShort {
                got: bytes.len(),
                need: HEADER_LEN,
            });
        }

        // INVARIANT: slice uzunluğu ≥ 16 yukarıda doğrulandı; aşağıdaki
        // try_into'lar sabit-array slice → array, infallible.
        #[allow(clippy::expect_used)] // INVARIANT: 8-byte slice → [u8; 8] sonsuz.
        let magic: [u8; 8] = bytes[0..8].try_into().expect("8-byte slice");
        if magic != HEKABUND_MAGIC {
            return Err(BundleError::MagicMismatch(magic));
        }

        #[allow(clippy::expect_used)] // INVARIANT: 4-byte slice → [u8; 4] sonsuz.
        let version_bytes: [u8; 4] = bytes[8..12].try_into().expect("4-byte slice");
        let version = u32::from_be_bytes(version_bytes);
        if version != HEKABUND_VERSION {
            return Err(BundleError::UnsupportedVersion(version));
        }

        #[allow(clippy::expect_used)] // INVARIANT: 4-byte slice → [u8; 4] sonsuz.
        let manifest_len_bytes: [u8; 4] = bytes[12..16].try_into().expect("4-byte slice");
        let manifest_len = u32::from_be_bytes(manifest_len_bytes);
        if manifest_len == 0 {
            return Err(BundleError::ManifestLenZero);
        }
        if manifest_len > MAX_MANIFEST_LEN {
            return Err(BundleError::ManifestLenExceeded {
                len: manifest_len,
                limit: MAX_MANIFEST_LEN,
            });
        }

        Ok(Self {
            version,
            manifest_len,
        })
    }
}

/// Streaming bundle writer — sender pipeline'ı kullanır.
///
/// Yaşam döngüsü:
/// 1. `BundleWriter::new(&manifest_json)` → header (16 byte) + `manifest_json`
///    bytes hash chain'e push edilir; ilk frame caller'a header + manifest
///    bytes'ı socket'e yazsın diye `header_bytes()` + `manifest_json` döner.
/// 2. her file body chunk'ı için `update(chunk)` → SHA-256 hasher'a feed.
/// 3. `finalize()` → trailer 32 byte döner; caller bunu socket'e yazar
///    bundle'ın sonunu mühürler.
///
/// **Caller sözleşmesi:** `update`'e geçirilen bayt sırası ve uzunluğu
/// `manifest.entries` içindeki file order ile **byte-exact** olmalı; aksi
/// halde receiver trailer fail eder. Writer bu sırayı kontrol etmez (caller
/// state machine'in işi).
#[derive(Debug)]
pub struct BundleWriter {
    hasher: Sha256,
    header_bytes: [u8; HEADER_LEN],
    /// Hash chain için tutulan stat (header + manifest + body toplamı).
    /// İleri PR'larda progress raporlama için public accessor düşünülebilir.
    written_so_far: u64,
}

impl BundleWriter {
    /// Yeni writer — header üret, header + `manifest_json` hash chain'e
    /// commit.
    ///
    /// Hatalar:
    /// - `manifest_json` boş → `ManifestLenZero`
    /// - `manifest_json.len() > MAX_MANIFEST_LEN` → `ManifestLenExceeded`
    /// - `manifest_json.len() > u32::MAX` (32-bit hedef): bu fonksiyon
    ///   doğrudan check eder, panic yok.
    pub fn new(manifest_json: &[u8]) -> Result<Self, BundleError> {
        if manifest_json.is_empty() {
            return Err(BundleError::ManifestLenZero);
        }
        // CLAUDE.md I-5: peer-controlled length; checked downcast.
        // 32-bit hedeflerde usize == u32 → try_from infallible. 64-bit
        // hedeflerde usize > u32::MAX olabilir (4 GiB+ manifest_json).
        // try_from None ise zaten MAX_MANIFEST_LEN (8 MiB) sınırının çok
        // üstünde — `len: u32::MAX` rapor.
        let manifest_len: u32 = match u32::try_from(manifest_json.len()) {
            Ok(n) => n,
            Err(_) => {
                // INVARIANT (CLAUDE.md I-3): TryFromIntError taşıyacak ek
                // bilgi yok; `BundleError::ManifestLenExceeded.len` field'ı
                // canonical reporting yeri. `_` discard pattern (NOT `_e`)
                // — workspace clippy::map_err_ignore lint kuralının
                // BYPASS değil, gerçek discard.
                return Err(BundleError::ManifestLenExceeded {
                    len: u32::MAX,
                    limit: MAX_MANIFEST_LEN,
                });
            }
        };
        if manifest_len > MAX_MANIFEST_LEN {
            return Err(BundleError::ManifestLenExceeded {
                len: manifest_len,
                limit: MAX_MANIFEST_LEN,
            });
        }

        let header = BundleHeader {
            version: HEKABUND_VERSION,
            manifest_len,
        };
        let header_bytes = header.encode();

        let mut hasher = Sha256::new();
        hasher.update(header_bytes);
        hasher.update(manifest_json);

        let written_so_far = (HEADER_LEN as u64) + u64::from(manifest_len);

        Ok(Self {
            hasher,
            header_bytes,
            written_so_far,
        })
    }

    /// Header bytes'ı döndür — caller socket'e yazar.
    #[must_use]
    pub fn header_bytes(&self) -> [u8; HEADER_LEN] {
        self.header_bytes
    }

    /// Dosya body chunk'ı hash chain'e feed et.
    pub fn update(&mut self, body_chunk: &[u8]) {
        self.hasher.update(body_chunk);
        // INVARIANT (CLAUDE.md I-5): `written_so_far` u64; chunk len usize.
        // saturating_add ile overflow defensive — pratikte u64 sınırına
        // (16 EiB) ulaşmadan diskler dolar.
        let chunk_len = u64::try_from(body_chunk.len()).unwrap_or(u64::MAX);
        self.written_so_far = self.written_so_far.saturating_add(chunk_len);
    }

    /// Şimdiye kadar hash'lenen byte sayısı (header + manifest + body).
    #[must_use]
    pub fn written_so_far(&self) -> u64 {
        self.written_so_far
    }

    /// Trailer üret — 32-byte SHA-256 digest.
    ///
    /// **Önemli:** finalize sonrası writer kullanılamaz hale gelir; tek-shot
    /// sözleşmesi.
    #[must_use]
    pub fn finalize(self) -> [u8; TRAILER_LEN] {
        self.hasher.finalize().into()
    }
}

/// Streaming bundle reader — receiver temp `.bundle` file'ını parse eder.
///
/// `open` çağrısı:
/// 1. Header (16 byte) read + decode (magic / version / `manifest_len` cap)
/// 2. Manifest JSON read (`manifest_len` byte; UTF-8 sınama caller'a — JSON
///    parser zaten UTF-8 enforce eder)
/// 3. Trailer offset hesabı: `bundle_len - 32`
/// 4. Trailer SHA-256 verify: `[0 .. bundle_len-32]` üzerinden hash hesapla,
///    constant-time karşılaştır.
///
/// Verify başarısızsa `BundleError::TrailerMismatch`. Verify OK ise reader
/// state'inde `manifest_json` bytes + header + `bundle_len` tutulur; PR-D'de
/// `into_extractor()` API'si entries iterate eder.
#[derive(Debug)]
pub struct BundleReader {
    file: File,
    header: BundleHeader,
    manifest_json: Vec<u8>,
    /// Toplam bundle boyutu (header + manifest + body + trailer).
    bundle_len: u64,
}

impl BundleReader {
    /// Bundle file'ını aç + header / manifest / trailer parse + verify.
    pub fn open(path: &std::path::Path) -> Result<Self, BundleError> {
        let mut file = File::open(path)?;
        let bundle_len = file.metadata()?.len();
        if bundle_len < (HEADER_LEN as u64).saturating_add(TRAILER_LEN as u64) {
            return Err(BundleError::BundleTooShort {
                got: bundle_len,
                need: (HEADER_LEN as u64).saturating_add(TRAILER_LEN as u64),
            });
        }

        // 1. Header
        let mut header_buf = [0u8; HEADER_LEN];
        file.read_exact(&mut header_buf)?;
        let header = BundleHeader::decode(&header_buf)?;

        // 2. manifest_len consistency: manifest + trailer payload sığmalı
        let manifest_end = (HEADER_LEN as u64).saturating_add(u64::from(header.manifest_len));
        let trailer_start = bundle_len.saturating_sub(TRAILER_LEN as u64);
        if manifest_end > trailer_start {
            return Err(BundleError::ManifestOverflowsBundle {
                manifest_len: header.manifest_len,
                bundle_len,
            });
        }

        // 3. Manifest JSON
        // INVARIANT (CLAUDE.md I-5): manifest_len ≤ MAX_MANIFEST_LEN (8 MiB)
        // BundleHeader::decode'da zaten doğrulandı; usize allocation güvenli.
        let mut manifest_json = vec![0u8; header.manifest_len as usize];
        file.read_exact(&mut manifest_json)?;

        // 4. Trailer + concat_data toplu hash
        // Hashlemek için file'ı baştan tekrar oku — header + manifest +
        // concat_data. Trailer'ı dışla.
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut remaining = trailer_start;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = u64::min(remaining, buf.len() as u64);
            // INVARIANT: want ≤ buf.len() ≤ usize::MAX; downcast güvenli.
            let want_us = usize::try_from(want).unwrap_or(buf.len());
            let n = file.read(&mut buf[..want_us])?;
            if n == 0 {
                return Err(BundleError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "bundle truncated during trailer verify",
                )));
            }
            hasher.update(&buf[..n]);
            // n ≤ remaining (want_us ≤ remaining; read returns ≤ buf len)
            remaining = remaining.saturating_sub(n as u64);
        }
        let computed: [u8; TRAILER_LEN] = hasher.finalize().into();

        // Trailer bytes
        let mut trailer = [0u8; TRAILER_LEN];
        file.read_exact(&mut trailer)?;

        // Constant-time compare (ConstantTimeEq module-top'tan).
        if !bool::from(computed.ct_eq(&trailer)) {
            return Err(BundleError::TrailerMismatch);
        }

        Ok(Self {
            file,
            header,
            manifest_json,
            bundle_len,
        })
    }

    /// Header accessor.
    #[must_use]
    pub fn header(&self) -> BundleHeader {
        self.header
    }

    /// Manifest JSON byte slice.
    #[must_use]
    pub fn manifest_json(&self) -> &[u8] {
        &self.manifest_json
    }

    /// Toplam bundle byte boyutu.
    #[must_use]
    pub fn bundle_len(&self) -> u64 {
        self.bundle_len
    }

    /// Concat-data byte boyutu (header + manifest + trailer çıkartılmış).
    #[must_use]
    pub fn concat_data_len(&self) -> u64 {
        self.bundle_len
            .saturating_sub(HEADER_LEN as u64)
            .saturating_sub(u64::from(self.header.manifest_len))
            .saturating_sub(TRAILER_LEN as u64)
    }

    /// File handle'ı consume + döndür (PR-D extractor için seek/read
    /// ihtiyacı). Caller offset'i `HEADER_LEN + manifest_len`'e seek etmeli.
    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }
}

/// `BundleWriter` / `BundleReader` hata kategorileri.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// Magic 8 byte `HEKABUND` değil — corrupt bundle veya wrong-format file.
    #[error("magic mismatch (expected HEKABUND, got {0:?})")]
    MagicMismatch([u8; 8]),

    /// `version` field'ı `HEKABUND_VERSION` değil — peer schema-bumped
    /// (`FOLDER_STREAM_V2`+) veya corrupt.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),

    /// `manifest_len > MAX_MANIFEST_LEN` (8 MiB) — denial-of-service guard.
    #[error("manifest_len {len} exceeds limit {limit}")]
    ManifestLenExceeded { len: u32, limit: u32 },

    /// `manifest_len == 0` — schema gereği version + `root_name` + …
    /// minimum yer tutmalı.
    #[error("manifest_len is zero")]
    ManifestLenZero,

    /// `manifest_len` payload sınırını aşıyor (header + manifest > `bundle_len`
    /// - trailer).
    #[error("manifest_len {manifest_len} overflows bundle (bundle_len = {bundle_len})")]
    ManifestOverflowsBundle { manifest_len: u32, bundle_len: u64 },

    /// Header read için en az `HEADER_LEN` byte gerekiyor.
    #[error("header too short: got {got} bytes, need {need}")]
    HeaderTooShort { got: usize, need: usize },

    /// Bundle dosyası header + trailer minimumundan kısa.
    #[error("bundle file too short: got {got} bytes, need at least {need}")]
    BundleTooShort { got: u64, need: u64 },

    /// Trailer SHA-256 hesabı bundle'daki son 32 byte ile eşleşmiyor —
    /// tampering veya disk corruption.
    #[error("trailer SHA-256 mismatch")]
    TrailerMismatch,

    /// Manifest JSON parse hatası (UTF-8, sözdizimi).
    #[error("manifest JSON parse error: {0}")]
    ManifestJson(#[from] serde_json::Error),

    /// Manifest schema-level validate hatası.
    #[error("manifest validation: {0}")]
    Manifest(#[from] ManifestError),

    /// I/O hatası (file read/write/seek).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_bundle_to_temp(manifest_json: &[u8], bodies: &[&[u8]]) -> NamedTempFile {
        let mut writer = BundleWriter::new(manifest_json).unwrap();
        let header_bytes = writer.header_bytes();

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&header_bytes).unwrap();
        tmp.write_all(manifest_json).unwrap();
        for body in bodies {
            tmp.write_all(body).unwrap();
            writer.update(body);
        }
        let trailer = writer.finalize();
        tmp.write_all(&trailer).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    // ------------------------------------------------------------------
    // BundleHeader tests
    // ------------------------------------------------------------------

    #[test]
    fn bundle_header_constants() {
        assert_eq!(HEKABUND_MAGIC, *b"HEKABUND");
        assert_eq!(HEKABUND_VERSION, 1);
        assert_eq!(HEADER_LEN, 16);
        assert_eq!(TRAILER_LEN, 32);
        assert_eq!(MAX_MANIFEST_LEN, 8 * 1024 * 1024);
    }

    #[test]
    fn bundle_header_encode_decode_roundtrip() {
        let header = BundleHeader {
            version: 1,
            manifest_len: 1234,
        };
        let bytes = header.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        // Magic is first 8 bytes
        assert_eq!(&bytes[0..8], &HEKABUND_MAGIC);
        // Version BE
        assert_eq!(&bytes[8..12], &[0, 0, 0, 1]);
        // manifest_len BE
        assert_eq!(&bytes[12..16], &[0, 0, 0x04, 0xD2]); // 1234 = 0x04D2

        let back = BundleHeader::decode(&bytes).unwrap();
        assert_eq!(back, header);
    }

    #[test]
    fn bundle_header_too_short_errors() {
        let bytes = [0u8; 10];
        let r = BundleHeader::decode(&bytes);
        assert!(matches!(
            r,
            Err(BundleError::HeaderTooShort { got: 10, need: 16 })
        ));
    }

    #[test]
    fn bundle_header_magic_mismatch_errors() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(b"NOTBUNDL");
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&100u32.to_be_bytes());
        let r = BundleHeader::decode(&bytes);
        assert!(matches!(r, Err(BundleError::MagicMismatch(_))));
    }

    #[test]
    fn bundle_header_version_unsupported_errors() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(&HEKABUND_MAGIC);
        bytes[8..12].copy_from_slice(&2u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&100u32.to_be_bytes());
        let r = BundleHeader::decode(&bytes);
        assert!(matches!(r, Err(BundleError::UnsupportedVersion(2))));
    }

    #[test]
    fn bundle_header_manifest_len_zero_errors() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(&HEKABUND_MAGIC);
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&0u32.to_be_bytes());
        let r = BundleHeader::decode(&bytes);
        assert!(matches!(r, Err(BundleError::ManifestLenZero)));
    }

    #[test]
    fn bundle_header_manifest_len_too_large_errors() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(&HEKABUND_MAGIC);
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&(MAX_MANIFEST_LEN + 1).to_be_bytes());
        let r = BundleHeader::decode(&bytes);
        assert!(matches!(r, Err(BundleError::ManifestLenExceeded { .. })));
    }

    // ------------------------------------------------------------------
    // BundleWriter tests
    // ------------------------------------------------------------------

    #[test]
    fn bundle_writer_rejects_empty_manifest() {
        let r = BundleWriter::new(&[]);
        assert!(matches!(r, Err(BundleError::ManifestLenZero)));
    }

    #[test]
    fn bundle_writer_rejects_oversized_manifest() {
        let big = vec![0u8; (MAX_MANIFEST_LEN as usize) + 1];
        let r = BundleWriter::new(&big);
        assert!(matches!(r, Err(BundleError::ManifestLenExceeded { .. })));
    }

    #[test]
    fn bundle_writer_finalize_matches_independent_sha256() {
        let manifest_json = br#"{"version":1,"root_name":"x","total_entries":0,"entries":[],"created_utc":"2026-01-01T00:00:00Z"}"#;
        let body_a: &[u8] = b"hello";
        let body_b: &[u8] = b"world";

        // Streaming
        let mut w = BundleWriter::new(manifest_json).unwrap();
        w.update(body_a);
        w.update(body_b);
        let trailer_streaming = w.finalize();

        // Independent
        let mut h = Sha256::new();
        let header = BundleHeader {
            version: 1,
            manifest_len: manifest_json.len() as u32,
        }
        .encode();
        h.update(header);
        h.update(manifest_json);
        h.update(body_a);
        h.update(body_b);
        let trailer_baseline: [u8; 32] = h.finalize().into();

        assert_eq!(trailer_streaming, trailer_baseline);
    }

    #[test]
    fn bundle_writer_written_so_far_tracks_bytes() {
        let manifest_json = br#"{"k":"v"}"#;
        let mut w = BundleWriter::new(manifest_json).unwrap();
        // header (16) + manifest (9)
        assert_eq!(w.written_so_far(), 25);
        w.update(&[0u8; 100]);
        assert_eq!(w.written_so_far(), 125);
        w.update(&[0u8; 50]);
        assert_eq!(w.written_so_far(), 175);
    }

    // ------------------------------------------------------------------
    // BundleReader tests
    // ------------------------------------------------------------------

    #[test]
    fn bundle_reader_open_roundtrip() {
        let manifest_json = br#"{"version":1,"root_name":"x","total_entries":0,"entries":[],"created_utc":"2026-01-01T00:00:00Z"}"#;
        let body_a: &[u8] = b"hello";
        let body_b: &[u8] = b"world";

        let tmp = write_bundle_to_temp(manifest_json, &[body_a, body_b]);
        let reader = BundleReader::open(tmp.path()).unwrap();
        assert_eq!(reader.header().version, 1);
        assert_eq!(reader.header().manifest_len as usize, manifest_json.len());
        assert_eq!(reader.manifest_json(), manifest_json);
        assert_eq!(reader.concat_data_len(), 10); // hello + world
    }

    #[test]
    fn bundle_reader_trailer_one_bit_flip_detected() {
        let manifest_json = br#"{"version":1,"root_name":"x","total_entries":0,"entries":[],"created_utc":"2026-01-01T00:00:00Z"}"#;
        let body: &[u8] = b"abcdefgh";

        let tmp = write_bundle_to_temp(manifest_json, &[body]);

        // Tamper: read all bytes, flip one body bit, write back to a new temp.
        let bytes = std::fs::read(tmp.path()).unwrap();
        let mut tampered = bytes.clone();
        // body offset = HEADER_LEN + manifest_len
        let body_offset = HEADER_LEN + manifest_json.len();
        tampered[body_offset] ^= 0x01;

        let tmp2 = NamedTempFile::new().unwrap();
        std::fs::write(tmp2.path(), &tampered).unwrap();

        let r = BundleReader::open(tmp2.path());
        assert!(matches!(r, Err(BundleError::TrailerMismatch)), "got {r:?}");
    }

    #[test]
    fn bundle_reader_truncated_file_rejected() {
        let manifest_json = br#"{"k":"v"}"#;
        let tmp = write_bundle_to_temp(manifest_json, &[b"x"]);

        // Truncate to less than HEADER + TRAILER.
        let truncated = std::fs::read(tmp.path()).unwrap();
        let tmp2 = NamedTempFile::new().unwrap();
        std::fs::write(tmp2.path(), &truncated[..10]).unwrap();

        let r = BundleReader::open(tmp2.path());
        assert!(matches!(r, Err(BundleError::BundleTooShort { .. })));
    }

    #[test]
    fn bundle_reader_magic_mismatch_rejected() {
        let manifest_json = br#"{"k":"v"}"#;
        let tmp = write_bundle_to_temp(manifest_json, &[b"x"]);

        let mut bytes = std::fs::read(tmp.path()).unwrap();
        bytes[0] = b'X'; // tamper magic
        let tmp2 = NamedTempFile::new().unwrap();
        std::fs::write(tmp2.path(), &bytes).unwrap();

        let r = BundleReader::open(tmp2.path());
        assert!(matches!(r, Err(BundleError::MagicMismatch(_))));
    }

    #[test]
    fn bundle_reader_concat_data_len_zero_for_no_files() {
        let manifest_json = br#"{"version":1,"root_name":"x","total_entries":0,"entries":[],"created_utc":"2026-01-01T00:00:00Z"}"#;
        let tmp = write_bundle_to_temp(manifest_json, &[]);
        let reader = BundleReader::open(tmp.path()).unwrap();
        assert_eq!(reader.concat_data_len(), 0);
        assert_eq!(
            reader.bundle_len(),
            (HEADER_LEN + manifest_json.len() + TRAILER_LEN) as u64
        );
    }
}
