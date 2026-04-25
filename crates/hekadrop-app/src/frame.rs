use crate::error::HekaError;
use bytes::{BufMut, Bytes, BytesMut};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Handshake fazında (ConnectionRequest, UKEY2) slow-loris saldırılarına karşı
/// frame okuma süresinin üst sınırı. 30 sn gerçek peer için fazlasıyla yeter;
/// bu sürede tek bir frame bile gelmezse saldırgan ya da ağ arızası varsayılır.
pub const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Şifreli loop (PayloadTransfer / KeepAlive) fazında idle üst sınır.
/// Quick Share peer'ları periyodik KeepAlive gönderdiği için 60 sn sessizlik
/// ölü bağlantı olarak kabul edilir; slow-loris tokio task sızıntısı
/// engellenir.
pub const STEADY_READ_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn read_frame(stream: &mut TcpStream) -> Result<Bytes, HekaError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(HekaError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// `read_frame` + deadline. Timeout → `HekaError::ReadTimeout`; böylece
/// çağıran taraf tokio task'ını bitirebilir ve socket kapatılır.
pub async fn read_frame_timeout(
    stream: &mut TcpStream,
    deadline: Duration,
) -> Result<Bytes, HekaError> {
    match tokio::time::timeout(deadline, read_frame(stream)).await {
        Ok(res) => res,
        Err(_) => Err(HekaError::ReadTimeout(deadline)),
    }
}

pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), HekaError> {
    let mut out = BytesMut::with_capacity(4 + data.len());
    out.put_u32(data.len() as u32);
    out.put_slice(data);
    stream.write_all(&out).await?;
    Ok(())
}
