//! FileMetadata.size defense-in-depth guard (M#7, v0.6.0).
//!
//! Protobuf `FileMetadata.size` alanı `int64`. Spec gereği **non-negative**
//! olmalı, ancak `prost` decode tarafında bu kısıtı uygulamaz — attacker
//! negatif ya da absürt büyük değer gönderebilir.
//!
//! Per-file etkileri:
//!   * **Negatif**: UI "-5 GB" gibi kozmetik bozukluk; `i64 → u64` cast
//!     yerine "wrap" değeri → `(written*100)/total` progress aritmetiği
//!     çöker. Payload katmanında zaten `total_size < 0` reddi var
//!     (`payload.rs` ~L289); Introduction aşamasında aynı belirsizliği
//!     UI'a taşımamak için burada clamp ediyoruz.
//!   * **Absürt büyük** (>`MAX_FILE_BYTES`): Her ne kadar `total_size` guard
//!     tek dosya seviyesinde yine payload katmanında reddetse de, Quick
//!     Share pratiğinde LAN üzerinden 1 TiB'tan büyük tek dosya yollamak
//!     meşru bir kullanım değil. Introduction aşamasında reddederek
//!     consent dialog'unda absürt boyut göstermemiş oluyoruz ve
//!     allocation + summary render maliyetini atlıyoruz.
//!
//! `payload.rs` içindeki `total_size` guard'ıyla aynı pattern'e uyar;
//! bu dosya yalnız **Introduction** aşamasında per-file karar verir.

/// Introduction aşamasında kabul edilecek tek dosya için üst sınır.
/// Quick Share spec'i formal bir limit tanımlamaz; pratik güvenli değer.
pub const MAX_FILE_BYTES: i64 = 1 << 40; // 1 TiB

/// `classify_file_size` çıktısı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSizeGuard {
    /// Spec'e uygun boyut — olduğu gibi kullanılır.
    Accept(i64),
    /// Negatif değerde UI/aritmetik güvenliği için 0'a clamp edildi.
    /// Çağıran taraf warn log atıp transferi kabul edebilir; attacker
    /// istemci bilgi olarak notlanır ama tek başına bağlantı kesme sebebi
    /// değildir (defense-in-depth).
    Clamped,
    /// Absürt büyük değer — Introduction tümüyle reddedilmeli, peer'a
    /// `Cancel` frame'i yollanıp bağlantı kapatılmalıdır.
    Reject,
}

/// Tek bir `FileMetadata.size` değerini sınıflandırır.
#[must_use]
pub fn classify_file_size(size: i64) -> FileSizeGuard {
    if size < 0 {
        FileSizeGuard::Clamped
    } else if size > MAX_FILE_BYTES {
        FileSizeGuard::Reject
    } else {
        FileSizeGuard::Accept(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_100mb() {
        assert_eq!(
            classify_file_size(100_000_000),
            FileSizeGuard::Accept(100_000_000)
        );
    }

    #[test]
    fn accepts_zero() {
        assert_eq!(classify_file_size(0), FileSizeGuard::Accept(0));
    }

    #[test]
    fn accepts_exactly_max() {
        assert_eq!(
            classify_file_size(MAX_FILE_BYTES),
            FileSizeGuard::Accept(MAX_FILE_BYTES)
        );
    }

    #[test]
    fn clamps_negative_one() {
        assert_eq!(classify_file_size(-1), FileSizeGuard::Clamped);
    }

    #[test]
    fn clamps_i64_min() {
        assert_eq!(classify_file_size(i64::MIN), FileSizeGuard::Clamped);
    }

    #[test]
    fn rejects_i64_max() {
        assert_eq!(classify_file_size(i64::MAX), FileSizeGuard::Reject);
    }

    #[test]
    fn rejects_one_tib_plus_one() {
        assert_eq!(
            classify_file_size(MAX_FILE_BYTES + 1),
            FileSizeGuard::Reject
        );
    }
}
