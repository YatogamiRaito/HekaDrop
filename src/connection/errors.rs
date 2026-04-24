//! UKEY2 handshake hata sınıflandırma — `anyhow::Error` → i18n key.

/// UKEY2 handshake sırasında oluşan `anyhow::Error`'ı kullanıcıya
/// gösterilecek bir i18n key'ine sınıflandırır.
///
/// Dalga 3 migration sonrası: tüm bail!() siteleri artık [`HekaError`]
/// variant'larına bağlı; downcast zinciri geniş, string-pattern fallback
/// kaldırıldı. Yalnız jenerik `HekaError::Ukey2(String)` için mesaj
/// içindeki semantik etiket (desteklenmeyen version / next_protocol / ...)
/// `err.handshake_insecure`'a eşlenir.
///
///   - `HekaError::ReadTimeout`            → `err.peer_timeout`
///   - `HekaError::UnexpectedEof`
///     / `HekaError::PeerDisconnected`
///     / `std::io::Error` (reset/closed)   → `err.peer_disconnected`
///   - `HekaError::Ukey2CommitmentMismatch` → `err.pin_mismatch` (MITM / yanlış PIN)
///   - `HekaError::Ukey2CipherDowngrade`
///     / `HekaError::Ukey2VersionDowngrade`
///     / `HekaError::Ukey2(_)`
///     / `HekaError::CipherCommitmentFlood`
///     / `HekaError::ProtocolState(_)`      → `err.handshake_insecure`
///   - diğer                                → jenerik `err.pin_mismatch`
///
/// Not: key'ler `src/i18n.rs` içinde paralel ajan tarafından ekleniyor.
pub(crate) fn classify_handshake_error(e: &anyhow::Error) -> &'static str {
    // Downcast — tip-safe dallar. String-pattern fallback Dalga 3
    // enum migration'ıyla birlikte kaldırıldı; tüm UKEY2 / handshake
    // hataları artık variant olarak geliyor.
    for cause in e.chain() {
        if let Some(he) = cause.downcast_ref::<crate::error::HekaError>() {
            match he {
                crate::error::HekaError::ReadTimeout(_) => return "err.peer_timeout",
                crate::error::HekaError::UnexpectedEof
                | crate::error::HekaError::PeerDisconnected => return "err.peer_disconnected",
                crate::error::HekaError::Io(io) => {
                    use std::io::ErrorKind::*;
                    return match io.kind() {
                        TimedOut => "err.peer_timeout",
                        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof
                        | NotConnected => "err.peer_disconnected",
                        _ => "err.peer_disconnected",
                    };
                }
                crate::error::HekaError::Ukey2CommitmentMismatch => return "err.pin_mismatch",
                crate::error::HekaError::Ukey2CipherDowngrade(_)
                | crate::error::HekaError::Ukey2VersionDowngrade(_)
                | crate::error::HekaError::Ukey2(_)
                | crate::error::HekaError::CipherCommitmentFlood(_)
                | crate::error::HekaError::ProtocolState(_) => return "err.handshake_insecure",
                _ => {}
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            return match io.kind() {
                TimedOut => "err.peer_timeout",
                ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected => {
                    "err.peer_disconnected"
                }
                _ => "err.peer_disconnected",
            };
        }
    }

    // Fallback: variant match etmedi — güvenlik-önemli olduğu için PIN
    // uyuşmazlığı mesajını göster (kullanıcı logs'a bakar).
    "err.pin_mismatch"
}
