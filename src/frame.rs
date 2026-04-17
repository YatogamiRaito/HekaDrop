use crate::error::HekaError;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

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

pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), HekaError> {
    let mut out = BytesMut::with_capacity(4 + data.len());
    out.put_u32(data.len() as u32);
    out.put_slice(data);
    stream.write_all(&out).await?;
    Ok(())
}
