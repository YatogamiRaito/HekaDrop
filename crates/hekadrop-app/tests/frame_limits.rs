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

//! Frame length-prefix sınır davranışları.
//!
//! `src/frame.rs` TCP stream üstünde `read_frame`/`write_frame` uygular; 4 bayt
//! big-endian u32 uzunluk + body. Bu entegrasyon testi aynı kontratı in-memory
//! cursor üzerinde mirror eder (`tests/frame_codec.rs` deseni ile aynı) —
//! production kodu değişmiyor, invariant'lar pin'leniyor.
//!
//! Pin'lenen davranışlar:
//!   * `frame_too_large_reddedilir` — 16 MiB üstü length-prefix reddedilmeli
//!     (MAX_FRAME_SIZE). Tam sınır değer kabul, +1 reddedilir.
//!   * `truncated_frame_eof_doner` — Length-prefix N bayt deklare edip socket
//!     N-k baytta kapanırsa read_exact EOF hatası döner (peer bağlantıyı
//!     yarıda kesti / slow-loris frame pompalama).
//!   * `zero_length_frame_davranisi` — **Kabul edilir** (mevcut davranış);
//!     üst katman boş payload'ı boş Vec olarak görür. Bu pin, ileride "zero
//!     reject" politikası eklenirse test'i güncellemeyi zorunlu kılar.
//!   * `huge_length_u32_max_reddedilir` — 32-bit platform'da `u32::MAX` gibi
//!     bir length cast'i usize'a genişler ama MAX_FRAME_SIZE check'i absürt
//!     değeri reddeder (DoS: 4 GiB alloc'u engeller).

use std::io::{Cursor, Read, Write};

/// `src/frame.rs` ile birebir aynı sabit. Değişirse production ile senkron tut.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0}")]
    TooLarge(usize),
    #[error("unexpected eof / truncated")]
    Eof,
}

/// `src/frame.rs::read_frame` ile aynı akış — cursor ergonomisi için mirror.
fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Eof
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
            FrameError::Eof
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(buf)
}

fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> Result<(), FrameError> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    Ok(())
}

#[test]
fn frame_too_large_reddedilir() {
    // MAX_FRAME_SIZE+1 → TooLarge. Sınırın 1 üstü = 16 MiB + 1.
    let too_big = (MAX_FRAME_SIZE as u32) + 1;
    let buf = too_big.to_be_bytes();
    let mut cur = Cursor::new(&buf[..]);
    let err = read_frame(&mut cur).expect_err("TooLarge dönmeli");
    match err {
        FrameError::TooLarge(n) => {
            assert_eq!(n, MAX_FRAME_SIZE + 1);
        }
        other => panic!("TooLarge beklendi, aldı: {other:?}"),
    }

    // Tam sınır değer (16 MiB) kabul — bu davranışı da pin'le.
    let boundary = MAX_FRAME_SIZE;
    let mut ok = Vec::with_capacity(4 + boundary);
    ok.extend_from_slice(&(boundary as u32).to_be_bytes());
    ok.resize(4 + boundary, 0);
    let mut cur = Cursor::new(&ok);
    let data = read_frame(&mut cur).expect("sınır değer kabul edilmeli");
    assert_eq!(data.len(), boundary);
}

#[test]
fn truncated_frame_eof_doner() {
    // Length 100 deklare ediliyor ama sadece 90 bayt body var — socket N-10'da kapandı.
    let declared: u32 = 100;
    let mut buf = Vec::new();
    buf.extend_from_slice(&declared.to_be_bytes());
    buf.extend(std::iter::repeat_n(0xAA, 90));
    let mut cur = Cursor::new(&buf);
    let err = read_frame(&mut cur).expect_err("truncated body EOF döndürmeli");
    assert!(
        matches!(err, FrameError::Eof),
        "Eof bekleniyor, aldı: {err:?}"
    );

    // Length-prefix bile tam gelmezse (2/4 bayt) yine EOF.
    let short = [0x00u8, 0x00];
    let mut cur = Cursor::new(&short[..]);
    let err = read_frame(&mut cur).expect_err("prefix truncated");
    assert!(
        matches!(err, FrameError::Eof),
        "Eof bekleniyor, aldı: {err:?}"
    );
}

#[test]
fn zero_length_frame_davranisi() {
    // Davranış pin: 0 length frame KABUL edilir, boş Vec döner. Üst katman
    // bu durumu kendi semantiğine göre yorumlar (örn. KeepAlive). Eğer
    // ileride "zero reject" eklenirse bu test kontrat değişikliğini zorlar.
    let mut buf = Vec::new();
    write_frame(&mut buf, b"").unwrap();
    assert_eq!(buf.as_slice(), &[0u8; 4], "sadece 4 bayt 0'lı prefix");

    let mut cur = Cursor::new(&buf);
    let got = read_frame(&mut cur).expect("zero-length kabul edilmeli");
    assert!(got.is_empty(), "body boş Vec dönmeli");
}

#[test]
fn huge_length_u32_max_reddedilir() {
    // u32::MAX (4 GiB - 1) → usize'a cast edildikten sonra MAX_FRAME_SIZE
    // check'i reddedecek. 32-bit platformda bile usize 4 GiB'i taşırmaz
    // (u32::MAX tam usize::MAX); ama 16 MiB üst limitine çarpıp TooLarge olur.
    // Bu, DoS koruması: 4 GiB alloc denemesi asla olmamalı.
    let huge = u32::MAX;
    let buf = huge.to_be_bytes();
    let mut cur = Cursor::new(&buf[..]);
    let err = read_frame(&mut cur).expect_err("u32::MAX reddedilmeli");
    match err {
        FrameError::TooLarge(n) => {
            // 32-bit: n == u32::MAX as usize. 64-bit: aynı. Her iki yönde de
            // MAX_FRAME_SIZE'ın çok üstündedir.
            assert!(n > MAX_FRAME_SIZE, "absürt değer: {n}");
        }
        other => panic!("TooLarge beklendi, aldı: {other:?}"),
    }
}
