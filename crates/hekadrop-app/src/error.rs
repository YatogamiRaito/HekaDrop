//! Domain-specific hata tipleri.
//!
//! `anyhow::Result<T>` kullanımı korunuyor — çoğu call-site `?` ile context
//! zincirliyor. Bu enum yalnızca **tip-safe ayrım** gerektiren yerler için:
//!
//!   * UI tarafının hataya göre farklı i18n key göstermesi (örn.
//!     `classify_handshake_error` downcast yolu).
//!   * Testlerin `assert_matches!` ile brittle `to_string().contains(...)`'
//!     yerine variant-bazlı assert yapabilmesi.
//!   * Güvenlik-kritik yollarda (HMAC, overrun, symlink) "ne tür hata"
//!     sorusunun string parsing'e bırakılmaması.
//!
//! Display string'leri bilinçli olarak **geriye uyumlu** tutuldu —
//! mevcut testler (`tests/*.rs`, `src/**/tests`) `err.to_string().contains(
//! "cipher downgrade" / "yalnız V1" / "HMAC" / "overrun" / "duplicate" /
//! "symlink" / "truncated" / "negatif" / "overflow" / "sequence" /
//! "cipher_commitment flood" / "absürt" / "SERVER_INIT") ...` substring
//! pattern'lerine güveniyor; bu token'ları variant display'lerinde koruduk.

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum HekaError {
    // ---- Transport / çerçeve ----
    /// I/O hatası (TCP reset, EOF, slow-loris timeout'u jeneriğe düşerse).
    /// `#[from]` — `?` ile `std::io::Error` otomatik dönüşüm için.
    #[error("I/O hatası: {0}")]
    Io(#[from] std::io::Error),
    /// `read_frame`: 4-byte length-prefix MAX_FRAME_SIZE'ı aştı.
    #[error("çerçeve boyutu sınır aştı: {0}")]
    FrameTooLarge(usize),
    /// `read_frame`: stream beklenmedik biçimde sonlandı (kısa okuma).
    #[error("beklenmeyen bağlantı sonu")]
    UnexpectedEof,
    /// `read_frame_timeout`: handshake/steady timeout aşıldı.
    #[error("frame okuma zaman aşımı ({0:?})")]
    ReadTimeout(std::time::Duration),
    /// Peer, karşılıklı disconnect protokolüne uymadan kapattı.
    #[error("peer beklenmedik biçimde bağlantıyı kesti")]
    PeerDisconnected,
    /// Rate limiter aynı IP'den pencere aşımı tespit etti (trusted muaf).
    #[error("rate limit: aynı IP'den çok fazla bağlantı denemesi ({0})")]
    RateLimited(String),
    /// TcpStream::connect üst sınırı aşıldı (erişilemez host / router drop).
    #[error("bağlantı zaman aşımına uğradı ({secs} sn): {addr}")]
    ConnectTimeout { secs: u64, addr: String },

    // ---- Crypto / secure channel ----
    /// HMAC tag alanı 32 bayt değil — truncation oracle / length-confusion
    /// saldırılarına karşı erken red.
    #[error("geçersiz HMAC tag uzunluğu: beklenen 32, gelen {0}")]
    HmacTagLength(usize),
    /// HMAC-SHA256 doğrulaması başarısız (bozulmuş / sahte mesaj).
    #[error("HMAC eşleşmedi")]
    HmacMismatch,
    /// Per-direction sequence counter i32 kapasitesini aştı (saldırgan
    /// `i32::MAX` gönderdiyse `checked_add` yakalar).
    #[error("sequence counter overflow ({side})")]
    SeqOverflow { side: &'static str },
    /// Decrypt sırasında sıra numarası beklenenle uyuşmadı (replay / reorder).
    #[error("sıra numarası uyuşmadı: beklenen {expected}, alınan {actual}")]
    SeqMismatch { expected: i32, actual: i32 },
    /// UKEY2 katmanı hatası — mesaj semantik etiketi (test substring'leri
    /// korunur).
    #[error("UKEY2: {0}")]
    Ukey2(String),
    /// UKEY2 ServerInit cipher downgrade reddedildi (P256_SHA512 dışı).
    #[error("ServerInit cipher downgrade reddedildi: beklenen P256_SHA512, gelen {0}")]
    Ukey2CipherDowngrade(String),
    /// UKEY2 ServerInit version downgrade reddedildi (V1 dışı).
    #[error("ServerInit version={0} — yalnız V1 destekleniyor")]
    Ukey2VersionDowngrade(String),
    /// UKEY2 ClientFinished commitment doğrulaması başarısız (PIN / MITM).
    #[error("UKEY2: cipher commitment uyuşmadı")]
    Ukey2CommitmentMismatch,

    // ---- Protocol / framing semantics ----
    /// Protobuf decode ya da beklenen alan eksikliği.
    #[error("protokol hatası: {0}")]
    Protocol(String),
    /// Beklenen state'te değiliz (örn. beklenen CLIENT_INIT, alınan X).
    #[error("protokol durumu: {0}")]
    ProtocolState(String),
    /// Introduction / CipherCommitment repeated-field flood (DoS).
    #[error("Introduction cardinality flood: {files} dosya, {texts} metin (limit 1000/64)")]
    IntroductionFlood { files: usize, texts: usize },
    /// UKEY2 CipherCommitment repeated-field flood (DoS).
    #[error("cipher_commitment flood: {0} eleman (max 8)")]
    CipherCommitmentFlood(usize),

    // ---- Payload / disk ----
    /// Cumulative overrun: kümülatif yazım toplamı `total_size`'ı aştı.
    #[error("payload overrun: id={id} written={written} > total_size={total}")]
    PayloadOverrun { id: i64, written: i64, total: i64 },
    /// Peer `last_chunk=true` attı ama toplam yazım bildirilen `total_size`'a
    /// ulaşmadı (silent truncation).
    #[error("truncated payload: id={id} written={written} total_size={total}")]
    PayloadTruncated { id: i64, written: i64, total: i64 },
    /// `FileMetadata` negatif / absürt büyük (>1 TiB) boyut.
    #[error("total_size negatif: {0}")]
    PayloadSizeNegative(i64),
    /// Deklare edilen boyut 1 TiB üstü.
    #[error("total_size absürt büyük: {0} bayt (>1 TiB limit)")]
    PayloadSizeAbsurd(i64),
    /// Path sanitization'dan sonra bile güvensiz path kombinasyonu.
    #[error("path traversal reddedildi: {0}")]
    PathTraversal(String),
    /// Hedef yer placeholder oluştuktan sonra symlink'e dönüştürülmüş (TOCTOU).
    #[error("hedef symlink — reddedildi (TOCTOU koruması): {0}")]
    SymlinkTarget(String),
    /// Aynı Introduction içinde aynı `payload_id` iki kez register edildi
    /// (silent overwrite saldırısı).
    #[error("duplicate payload_id={0} — destination overwrite reddedildi")]
    DuplicatePayloadId(i64),
    /// Unique dosya adı 10k denemede bulunamadı (dizin dolu).
    #[error("uygun dosya adı bulunamadı (10k deneme)")]
    FileNameExhausted,
    /// Payload katmanı IO (disk full, permission, generic std::io wrap
    /// etmesek de context string taşıyanlar).
    #[error("payload IO: {0}")]
    PayloadIo(String),
    /// `total_bytes` / `file_size` i64 overflow.
    #[error("toplam bayt i64 kapasitesini aştı")]
    ByteCountOverflow,
    /// Gönderici dosya yok.
    #[error("dosya bulunamadı: {0}")]
    FileNotFound(String),
    /// Gönderici boş dosya(lar) (toplam 0 bayt).
    #[error("boş dosya gönderilemez (toplam 0 bayt)")]
    EmptyPayload,
    /// Gönderici hiç dosya seçmedi (0 dosya). `EmptyPayload`'dan farklı —
    /// "0 bayt dosya" değil, "hiç dosya yok".
    #[error("hiç dosya seçilmedi")]
    NoFilesSelected,
    /// Tek dosya boyutu i64::MAX üstü (saçma büyük).
    #[error("dosya çok büyük (>= {max} bayt, desteklenmiyor): {path}")]
    FileTooLarge { max: i64, path: String },

    // ---- Cancel / flow ----
    /// Kullanıcı aktarımı iptal etti (UI cancel token).
    #[error("kullanıcı aktarımı iptal etti")]
    UserCancelled,
    /// Peer Cancel sharing frame gönderdi.
    #[error("Peer aktarımı iptal etti")]
    PeerCancelled,
    /// Chunk gönderim sırasında cancel tetiklendi.
    #[error("chunk gönderim sırasında iptal")]
    CancelledDuringChunk,
    /// Peer Response status=reject (çoğunlukla PIN uyuşmazlığı).
    #[error("Peer aktarımı reddetti (status={status}). Session fingerprint: {fingerprint} — PIN eşleşmedi mi?")]
    PeerRejected { status: i32, fingerprint: String },

    // ---- Settings / config ----
    /// İndirme dizini doğrulaması başarısız.
    #[error("indirme dizini geçersiz: {path}: {reason}")]
    DownloadDirInvalid { path: String, reason: String },
    /// Config dosyası migration hatası (schema versiyonu / parse).
    #[error("config migration: {0}")]
    ConfigMigration(String),
}
