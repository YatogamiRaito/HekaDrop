// Test/bench dosyası — production lint'leri test idiomatik kullanımı bozmasın.
// Cast/clone family de gevşek: test verisi hardcoded, numerik safety burada
// odak değil; behavior validation odaklıyız.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::expect_fun_call,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::ignored_unit_patterns,
    clippy::use_self,
    clippy::trivially_copy_pass_by_ref,
    clippy::single_match_else,
    clippy::map_err_ignore
)]

//! Frame codec: big-endian u32 length-prefix + protobuf body.
//!
//! HekaDrop `src/frame.rs` bu kontratı TcpStream üstünde uygular. Burada stream
//! yerine in-memory cursor kullanarak `read_frame`/`write_frame` davranışını
//! simüle eder; uzunluk overflow, truncation, protobuf uyumluluğu (prost)
//! senaryoları kapsanır.

use prost::Message;
use std::io::{Cursor, Read, Write};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0}")]
    TooLarge(usize),
    #[error("truncated")]
    Truncated,
}

fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> Result<(), FrameError> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    Ok(())
}

fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(buf)
}

/// prost tarafından üretilen `DeviceToDeviceMessage` için minimal proto
/// (build.rs'e bağımlılık olmadan bağımsız test'in kendi kendine yeter olması).
#[derive(Clone, PartialEq, Message)]
struct TestFrameBody {
    #[prost(bytes = "vec", optional, tag = "1")]
    payload: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    sequence: Option<i32>,
}

#[test]
fn roundtrip_basit() {
    let data = b"merhaba frame";
    let mut buf = Vec::new();
    write_frame(&mut buf, data).unwrap();
    assert_eq!(buf.len(), 4 + data.len());
    // İlk 4 byte big-endian uzunluk
    assert_eq!(&buf[..4], &(data.len() as u32).to_be_bytes());
    let mut cur = Cursor::new(&buf);
    let read = read_frame(&mut cur).unwrap();
    assert_eq!(read, data);
}

#[test]
fn uzunluk_prefix_big_endian() {
    let mut buf = Vec::new();
    // 258 bayt data → BE: [0x00, 0x00, 0x01, 0x02]
    let data = vec![0x42u8; 258];
    write_frame(&mut buf, &data).unwrap();
    assert_eq!(&buf[..4], &[0x00, 0x00, 0x01, 0x02]);
}

#[test]
fn ard_arda_frame_okuma() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"one").unwrap();
    write_frame(&mut buf, b"two").unwrap();
    write_frame(&mut buf, b"three").unwrap();
    let mut cur = Cursor::new(&buf);
    assert_eq!(read_frame(&mut cur).unwrap(), b"one");
    assert_eq!(read_frame(&mut cur).unwrap(), b"two");
    assert_eq!(read_frame(&mut cur).unwrap(), b"three");
}

#[test]
fn truncated_length_prefix_hata_doner() {
    let buf = [0x00u8, 0x00, 0x01]; // 4. byte eksik
    let mut cur = Cursor::new(&buf[..]);
    let err = read_frame(&mut cur).expect_err("truncated hata bekleniyor");
    assert!(matches!(err, FrameError::Truncated), "err={err:?}");
}

#[test]
fn truncated_body_hata_doner() {
    // Prefix 10 byte declare ediyor, ama sadece 3 byte body var
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x0A];
    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    let mut cur = Cursor::new(&buf);
    let err = read_frame(&mut cur).expect_err("truncated body");
    assert!(matches!(err, FrameError::Truncated), "err={err:?}");
}

#[test]
fn sifir_byte_frame_kabul_edilir() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"").unwrap();
    assert_eq!(buf.as_slice(), &[0x00u8, 0x00, 0x00, 0x00]);
    let mut cur = Cursor::new(&buf);
    let data = read_frame(&mut cur).unwrap();
    assert!(data.is_empty());
}

#[test]
fn cok_buyuk_frame_reddedilir() {
    // Prefix 17 MB declare — MAX_FRAME_SIZE (16 MB) üstünde
    let too_big = 17 * 1024 * 1024u32;
    let buf = too_big.to_be_bytes();
    let mut cur = Cursor::new(&buf[..]);
    let err = read_frame(&mut cur).expect_err("TooLarge");
    match err {
        FrameError::TooLarge(n) => assert_eq!(n as u32, too_big),
        _ => panic!("TooLarge beklendi, got: {err:?}"),
    }
}

#[test]
fn protobuf_encode_decode_roundtrip() {
    let msg = TestFrameBody {
        payload: Some(vec![1, 2, 3, 4, 5]),
        sequence: Some(42),
    };
    let encoded = msg.encode_to_vec();
    // Protobuf encode etmeli
    assert!(!encoded.is_empty());

    // Frame'e sar
    let mut buf = Vec::new();
    write_frame(&mut buf, &encoded).unwrap();
    // Oku → decode
    let mut cur = Cursor::new(&buf);
    let frame_body = read_frame(&mut cur).unwrap();
    let decoded = TestFrameBody::decode(&frame_body[..]).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn protobuf_bozuk_body_decode_hata() {
    // Geçersiz protobuf → decode Err dönmeli
    let bad = [0xFFu8, 0xFF, 0xFF, 0x00];
    let r = TestFrameBody::decode(&bad[..]);
    assert!(r.is_err(), "bozuk protobuf hata vermeli");
}

#[test]
fn protobuf_eksik_optional_default() {
    // Boş protobuf → tüm optional None
    let empty: Vec<u8> = vec![];
    let decoded = TestFrameBody::decode(&empty[..]).unwrap();
    assert_eq!(decoded.payload, None);
    assert_eq!(decoded.sequence, None);
}

#[test]
fn max_frame_size_sinir_kabul() {
    // Tam sınır değer — 16 MB kabul edilmeli (MAX_FRAME_SIZE inclusive)
    let boundary = MAX_FRAME_SIZE;
    let mut buf = Vec::with_capacity(4 + boundary);
    buf.extend_from_slice(&(boundary as u32).to_be_bytes());
    // Body'yi sıfırlarla doldur — gerçekten okuyabilmesi için 16 MB yer lazım
    buf.resize(4 + boundary, 0);
    let mut cur = Cursor::new(&buf);
    let data = read_frame(&mut cur).unwrap();
    assert_eq!(data.len(), boundary);
}

#[test]
fn length_prefix_endian_ters_yonde_yanlis_yorumlanir() {
    // Little-endian olarak 3 bayt data yazmaya çalışırsak, BE parser bunu
    // 0x03000000 = 50 MB olarak görecek ve TooLarge veya Truncated atacak.
    // Bu test, BE kontratının zorlayıcı olduğunu doğrular.
    let buf_le = [0x03u8, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC]; // little-endian yazılmış
    let mut cur = Cursor::new(&buf_le[..]);
    let result = read_frame(&mut cur);
    assert!(result.is_err(), "LE prefix BE parser'da hata vermeli");
}
