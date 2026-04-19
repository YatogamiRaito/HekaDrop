use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum HekaError {
    #[error("protokol hatası: {0}")]
    Protocol(String),
    #[error("I/O hatası: {0}")]
    Io(#[from] std::io::Error),
    #[error("çerçeve boyutu sınır aştı: {0}")]
    FrameTooLarge(usize),
    #[error("beklenmeyen bağlantı sonu")]
    UnexpectedEof,
    #[error("frame okuma zaman aşımı ({0:?})")]
    ReadTimeout(std::time::Duration),
}
