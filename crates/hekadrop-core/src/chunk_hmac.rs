//! RFC-0003 — Per-chunk HMAC-SHA256 integrity tag.
//!
//! Quick Share'in mevcut [`crate::secure::SecureCtx`]'i her frame için
//! AES-256-CBC + HMAC-SHA256 ile wire transit integrity'sini sağlar; bu
//! modül **buna alternatif değildir**. Üç farklı ihtiyacı karşılar:
//!
//! 1. **Resume preconditions** (RFC-0004 §3.4): receiver yarım dosyadaki
//!    byte aralığını O(1) doğrulayabilsin — sender resume hint'inden
//!    sonra yerel hash'i hesaplamadan tag karşılaştırarak fast-path.
//! 2. **Storage corruption early-abort:** `frame::read_frame` (wire'da
//!    verified) ile disk flush arasında bir ara katman bayt değiştirirse
//!    sonraki chunk'ın tag verify'ı yakalar.
//! 3. **Partial integrity primitif'i:** RFC-0005 (folder bundle) per-file
//!    resume / mid-bundle abort için chunk tag'lerini reuse eder.
//!
//! Wire-byte-exact spec: [`docs/protocol/chunk-hmac.md`].
//! Capabilities gate: [`crate::capabilities::features::CHUNK_HMAC_V1`].

use crate::crypto::{hkdf_sha256, hmac_sha256};
use hekadrop_proto::hekadrop_ext::ChunkIntegrity;
use subtle::ConstantTimeEq;

/// HKDF info label — wire kontrat kilidi. Değiştirmek `chunk_hmac_v2` bumpı
/// gerektirir (yeni capability bit).
pub const CHUNK_HMAC_HKDF_INFO: &[u8] = b"hekadrop chunk-hmac v1";

/// HMAC-SHA256 tag uzunluğu — sabit 32 byte, başka değer protokol ihlali.
pub const TAG_LEN: usize = 32;

/// HMAC input prefix uzunluğu (body öncesi sabit alanlar).
/// Hesap: 8 (`payload_id` BE i64) + 8 (`chunk_index` BE i64) + 8 (offset BE i64)
///       + 4 (`body_len` BE u32) = 28 bayt.
pub const HMAC_INPUT_PREFIX_LEN: usize = 8 + 8 + 8 + 4;

/// UKEY2 `next_secret` IKM'inden chunk-HMAC anahtarını türet.
///
/// HKDF-SHA256(salt = empty, info = `"hekadrop chunk-hmac v1"`, len = 32).
/// Wire kontrat: label kilitlidir; v1 boyunca aynı kalır.
#[must_use]
pub fn derive_chunk_hmac_key(next_secret: &[u8]) -> [u8; 32] {
    let derived = hkdf_sha256(next_secret, &[], CHUNK_HMAC_HKDF_INFO, TAG_LEN);
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&derived);
    out
}

/// HMAC-SHA256 input'unun canonical encoding'ini üret.
///
/// Layout: `payload_id(BE i64) ‖ chunk_index(BE i64) ‖ offset(BE i64) ‖
///          body_len(BE u32) ‖ body`. Big-endian seçimi cross-platform
/// reproducibility içindir (debug log/fuzz corpus tutarlılığı).
fn build_hmac_input(payload_id: i64, chunk_index: i64, offset: i64, body: &[u8]) -> Vec<u8> {
    // SAFETY-CAST: body_len u32 alanı — body 4 GiB'i aşmamalı (Quick Share
    // chunk pratiği 512 KiB; bu bir invariant ama u32 üst sınırı 4 GiB).
    // Cast'ten önce truncation kontrol et; aşılmışsa caller'a u32::MAX
    // boyu döner ve verify mismatch ile yakalanır (defensive — hot path
    // panic kullanmaz, error caller'da raise olur).
    #[allow(clippy::cast_possible_truncation)]
    let body_len_u32 = u32::try_from(body.len()).unwrap_or(u32::MAX);

    let mut input = Vec::with_capacity(HMAC_INPUT_PREFIX_LEN + body.len());
    input.extend_from_slice(&payload_id.to_be_bytes());
    input.extend_from_slice(&chunk_index.to_be_bytes());
    input.extend_from_slice(&offset.to_be_bytes());
    input.extend_from_slice(&body_len_u32.to_be_bytes());
    input.extend_from_slice(body);
    input
}

/// Bir chunk için HMAC-SHA256 tag hesapla.
///
/// Sender bunu `PayloadTransferFrame` gönderdikten hemen sonra
/// [`build_chunk_integrity`] ile wrap edip envelope'a koyar.
#[must_use]
pub fn compute_tag(
    chunk_hmac_key: &[u8; 32],
    payload_id: i64,
    chunk_index: i64,
    offset: i64,
    body: &[u8],
) -> [u8; 32] {
    let input = build_hmac_input(payload_id, chunk_index, offset, body);
    hmac_sha256(chunk_hmac_key, &input)
}

/// Receiver-side: peer'ın yolladığı [`ChunkIntegrity`] mesajını local
/// olarak ingest edilen chunk body'siyle doğrula.
///
/// Kontrol sırası (`docs/protocol/chunk-hmac.md` §5):
///   1. `tag.len() == 32` (constant-time-irrelevant; attacker-controlled length)
///   2. `body_len` consistency (cheap)
///   3. HMAC compute
///   4. Constant-time compare ([`subtle::ConstantTimeEq`])
///
/// Length check'in constant-time karşılaştırmadan ÖNCE yapılması bir timing
/// side-channel açmaz: tag uzunluğu peer'dan gelir, secret değildir.
pub fn verify_tag(
    chunk_hmac_key: &[u8; 32],
    expected: &ChunkIntegrity,
    body: &[u8],
) -> Result<(), VerifyError> {
    // Adım 1: tag uzunluğu kilitli 32 byte.
    if expected.tag.len() != TAG_LEN {
        return Err(VerifyError::WrongTagLength(expected.tag.len()));
    }

    // Adım 2: body_len consistency. ChunkIntegrity.body_len peer'dan gelen
    // bir iddia; yerel body uzunluğuyla eşleşmeli. Mismatch protokol ihlali.
    if expected.body_len as usize != body.len() {
        return Err(VerifyError::BodyLenMismatch {
            claimed: expected.body_len as usize,
            actual: body.len(),
        });
    }

    // Adım 3: HMAC compute. Tag binding redundant alanları (payload_id,
    // chunk_index, offset) içerdiği için herhangi biri tampered ise
    // verify fail eder.
    let computed = compute_tag(
        chunk_hmac_key,
        expected.payload_id,
        expected.chunk_index,
        expected.offset,
        body,
    );

    // Adım 4: constant-time compare.
    if computed.ct_eq(&expected.tag).into() {
        Ok(())
    } else {
        Err(VerifyError::TagMismatch)
    }
}

/// Sender-side helper: hesaplanan tag'i `ChunkIntegrity` protobuf
/// mesajına paketle. `crate::frame::wrap_hekadrop_frame` ile magic prefix
/// eklenir, sonra `SecureCtx::encrypt`'e beslenir.
#[must_use]
pub fn build_chunk_integrity(
    payload_id: i64,
    chunk_index: i64,
    offset: i64,
    body_len: usize,
    tag: [u8; 32],
) -> ChunkIntegrity {
    // SAFETY-CAST: aynı u32 sınırı `build_hmac_input` ile tutarlı.
    #[allow(clippy::cast_possible_truncation)]
    let body_len_u32 = u32::try_from(body_len).unwrap_or(u32::MAX);

    ChunkIntegrity {
        payload_id,
        chunk_index,
        offset,
        body_len: body_len_u32,
        tag: tag.to_vec().into(),
    }
}

/// `verify_tag` hata kategorileri.
///
/// Receiver bunları log'a yazarken **tag content'ini ASLA loglamaz**;
/// sadece kategori + length mismatch'te tag length değeri loggable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// Tag uzunluğu 32 byte değil (protokol ihlali).
    #[error("ChunkIntegrity.tag uzunluğu {0} byte; 32 olmalı")]
    WrongTagLength(usize),

    /// `body_len` field'ı yerel body uzunluğuyla eşleşmiyor.
    #[error("ChunkIntegrity.body_len {claimed} ≠ yerel body {actual}")]
    BodyLenMismatch { claimed: usize, actual: usize },

    /// HMAC compute eşleşmedi — kasıtlı tampering veya storage corruption.
    /// Hata mesajı içerik leak etmez (chunk identifier'lar caller'da loglu).
    #[error("ChunkIntegrity tag eşleşmedi (HMAC mismatch)")]
    TagMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HKDF label kilidini sabitler — değişirse v2 capability bumpı şart.
    #[test]
    fn hkdf_info_label_locked() {
        assert_eq!(CHUNK_HMAC_HKDF_INFO, b"hekadrop chunk-hmac v1");
    }

    #[test]
    fn tag_length_constant() {
        assert_eq!(TAG_LEN, 32);
    }

    #[test]
    fn hmac_input_prefix_len_constant() {
        assert_eq!(HMAC_INPUT_PREFIX_LEN, 28);
    }

    /// HKDF derivation deterministik — aynı IKM iki kez aynı key üretir.
    #[test]
    fn key_derivation_deterministic() {
        let ikm = [0x42u8; 32];
        let k1 = derive_chunk_hmac_key(&ikm);
        let k2 = derive_chunk_hmac_key(&ikm);
        assert_eq!(k1, k2);
    }

    /// Farklı IKM → farklı key (HKDF doğru çalışıyor).
    #[test]
    fn key_derivation_distinguishes_ikm() {
        let k1 = derive_chunk_hmac_key(&[0x42u8; 32]);
        let k2 = derive_chunk_hmac_key(&[0x43u8; 32]);
        assert_ne!(k1, k2);
    }

    /// Domain separation: chunk-HMAC label başka label'lardan farklı key
    /// üretir. `SecureMessage` HKDF (different info) ile çakışma olmamalı.
    #[test]
    fn key_derivation_domain_separated() {
        let ikm = [0x42u8; 32];
        let chunk_key = derive_chunk_hmac_key(&ikm);
        // Hipotetik farklı label (gerçek SecureMessage label'ı `secure_message_salt()`
        // kullanır salt olarak; biz info-tabanlı domain separation gösteriyoruz).
        let other = hkdf_sha256(&ikm, &[], b"hekadrop other v1", TAG_LEN);
        assert_ne!(chunk_key.as_slice(), other.as_slice());
    }

    /// Round-trip: `compute_tag` + `verify_tag` (eşleşen body) → Ok.
    #[test]
    fn compute_then_verify_ok() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"the quick brown fox jumps over the lazy dog";
        let tag = compute_tag(&key, 1234, 5, 0x100, body);

        let ci = build_chunk_integrity(1234, 5, 0x100, body.len(), tag);
        assert_eq!(verify_tag(&key, &ci, body), Ok(()));
    }

    /// Body bit-flip → `TagMismatch`.
    #[test]
    fn verify_detects_body_tampering() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"original".to_vec();
        let tag = compute_tag(&key, 1, 0, 0, &body);

        let mut tampered = body.clone();
        tampered[0] ^= 0x01;
        let ci = build_chunk_integrity(1, 0, 0, tampered.len(), tag);
        assert_eq!(
            verify_tag(&key, &ci, &tampered),
            Err(VerifyError::TagMismatch)
        );
    }

    /// Yanlış `payload_id` → `TagMismatch` (tag binding redundant alanları içerir).
    #[test]
    fn verify_detects_payload_id_rebinding() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"data";
        let tag = compute_tag(&key, 100, 0, 0, body);

        // Saldırgan ChunkIntegrity'de payload_id'yi 100→200 değiştirmiş gibi
        // — body aynı ama tag 100 için hesaplanmış. Verify yakalamalı.
        let ci = ChunkIntegrity {
            payload_id: 200, // değişti
            chunk_index: 0,
            offset: 0,
            body_len: body.len() as u32,
            tag: tag.to_vec().into(),
        };
        assert_eq!(verify_tag(&key, &ci, body), Err(VerifyError::TagMismatch));
    }

    /// Yanlış `chunk_index` → `TagMismatch`.
    #[test]
    fn verify_detects_chunk_index_rebinding() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"x";
        let tag = compute_tag(&key, 1, 5, 0, body);

        let ci = ChunkIntegrity {
            payload_id: 1,
            chunk_index: 6, // değişti
            offset: 0,
            body_len: 1,
            tag: tag.to_vec().into(),
        };
        assert_eq!(verify_tag(&key, &ci, body), Err(VerifyError::TagMismatch));
    }

    /// Yanlış offset → `TagMismatch`.
    #[test]
    fn verify_detects_offset_rebinding() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"x";
        let tag = compute_tag(&key, 1, 0, 100, body);

        let ci = ChunkIntegrity {
            payload_id: 1,
            chunk_index: 0,
            offset: 200, // değişti
            body_len: 1,
            tag: tag.to_vec().into(),
        };
        assert_eq!(verify_tag(&key, &ci, body), Err(VerifyError::TagMismatch));
    }

    /// Yanlış key → `TagMismatch`.
    #[test]
    fn verify_detects_wrong_key() {
        let k1 = derive_chunk_hmac_key(&[0x42u8; 32]);
        let k2 = derive_chunk_hmac_key(&[0x43u8; 32]);
        let body = b"x";
        let tag = compute_tag(&k1, 1, 0, 0, body);

        let ci = build_chunk_integrity(1, 0, 0, 1, tag);
        assert_eq!(verify_tag(&k2, &ci, body), Err(VerifyError::TagMismatch));
    }

    /// Tag uzunluğu 32 değil → `WrongTagLength` (constant-time öncesi).
    #[test]
    fn verify_rejects_short_tag() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"x";
        let mut ci = build_chunk_integrity(1, 0, 0, 1, [0u8; 32]);
        ci.tag = vec![0u8; 16].into(); // çok kısa
        assert_eq!(
            verify_tag(&key, &ci, body),
            Err(VerifyError::WrongTagLength(16))
        );
    }

    #[test]
    fn verify_rejects_long_tag() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"x";
        let mut ci = build_chunk_integrity(1, 0, 0, 1, [0u8; 32]);
        ci.tag = vec![0u8; 64].into(); // çok uzun
        assert_eq!(
            verify_tag(&key, &ci, body),
            Err(VerifyError::WrongTagLength(64))
        );
    }

    #[test]
    fn verify_rejects_empty_tag() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"x";
        let mut ci = build_chunk_integrity(1, 0, 0, 1, [0u8; 32]);
        ci.tag = vec![].into();
        assert_eq!(
            verify_tag(&key, &ci, body),
            Err(VerifyError::WrongTagLength(0))
        );
    }

    /// `body_len` mismatch → `BodyLenMismatch` (HMAC compute öncesi yakalanır).
    #[test]
    fn verify_rejects_body_len_mismatch() {
        let key = derive_chunk_hmac_key(&[0x42u8; 32]);
        let body = b"abcdefgh"; // 8 byte
        let tag = compute_tag(&key, 1, 0, 0, body);

        let mut ci = build_chunk_integrity(1, 0, 0, body.len(), tag);
        ci.body_len = 4; // claim 4 ama actual 8
        assert_eq!(
            verify_tag(&key, &ci, body),
            Err(VerifyError::BodyLenMismatch {
                claimed: 4,
                actual: 8
            })
        );
    }

    /// Empty body — boş chunk için tag hesaplanabilmeli (edge case).
    #[test]
    fn empty_body_roundtrip() {
        let key = derive_chunk_hmac_key(&[0u8; 32]);
        let body: &[u8] = &[];
        let tag = compute_tag(&key, 0, 0, 0, body);
        let ci = build_chunk_integrity(0, 0, 0, 0, tag);
        assert_eq!(verify_tag(&key, &ci, body), Ok(()));
    }

    /// HMAC input prefix layout — byte-by-byte spec doğrulaması.
    /// chunk-hmac.md §4.2 canonical encoding kontratı.
    #[test]
    fn hmac_input_canonical_layout() {
        // payload_id = 0x12345678, chunk_index = 0x03, offset = 0x180000,
        // body_len = 32 (chunk-hmac.md §3.1 örnek değerleri).
        let body = vec![0x41u8; 32]; // 'A' × 32
        let input = build_hmac_input(0x12345678, 3, 0x180000, &body);

        // Layout: 8B payload_id BE | 8B chunk_index BE | 8B offset BE | 4B body_len BE | body
        assert_eq!(input.len(), 28 + 32);

        // payload_id (BE i64): 00 00 00 00 12 34 56 78
        assert_eq!(&input[0..8], &[0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]);
        // chunk_index (BE i64): 00 00 00 00 00 00 00 03
        assert_eq!(&input[8..16], &[0, 0, 0, 0, 0, 0, 0, 3]);
        // offset (BE i64): 00 00 00 00 00 18 00 00
        assert_eq!(&input[16..24], &[0, 0, 0, 0, 0, 0x18, 0, 0]);
        // body_len (BE u32): 00 00 00 20
        assert_eq!(&input[24..28], &[0, 0, 0, 32]);
        // body
        assert_eq!(&input[28..], &body[..]);
    }

    /// Chunk index'leri sıralı ama farklı `payload_id`'lerde aynı body için
    /// farklı tag çıkarmalı (binding redundancy doğrulaması).
    #[test]
    fn different_payload_ids_produce_different_tags_for_same_body() {
        let key = derive_chunk_hmac_key(&[0u8; 32]);
        let body = b"shared body";
        let t1 = compute_tag(&key, 1, 0, 0, body);
        let t2 = compute_tag(&key, 2, 0, 0, body);
        assert_ne!(t1, t2);
    }

    /// Aynı tüm parametreler farklı body → farklı tag.
    #[test]
    fn different_body_produces_different_tag() {
        let key = derive_chunk_hmac_key(&[0u8; 32]);
        let t1 = compute_tag(&key, 1, 0, 0, b"a");
        let t2 = compute_tag(&key, 1, 0, 0, b"b");
        assert_ne!(t1, t2);
    }

    /// `build_chunk_integrity` field'ları doğru maps yapar.
    #[test]
    fn build_chunk_integrity_field_mapping() {
        let tag = [0xABu8; 32];
        let ci = build_chunk_integrity(0x111, 0x222, 0x333, 64, tag);
        assert_eq!(ci.payload_id, 0x111);
        assert_eq!(ci.chunk_index, 0x222);
        assert_eq!(ci.offset, 0x333);
        assert_eq!(ci.body_len, 64);
        assert_eq!(ci.tag.len(), 32);
        assert_eq!(&ci.tag[..], &tag[..]);
    }
}
