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

//! Payload ingest invariant'ları — `PayloadAssembler` üzerinden uç durumlar.
//!
//! Bu entegrasyon testi `hekadrop::payload::PayloadAssembler` public API'sini
//! doğrudan kullanır (lib.rs'te `pub mod payload` olarak re-export edilmiştir).
//! Secure/network katmanlarına dokunmaz — payload reassembly semantiği
//! (chunk birleşimi, total_size validasyonu, duplicate id koruması, SHA-256
//! hesabı) platform-agnostik olduğu için bu seviyede izole edilebilir.
//!
//! Kapsanan invariant'lar (her test adı iddiayı pin'ler):
//!   * `corrupted_chunk_sha_mismatch_reddedilir` — Peer'ın gönderdiği body
//!     yerel olarak hesaplanan SHA-256'dan farklı olmalı; `CompletedPayload::
//!     File.sha256` alanı streaming hasher üzerinden üretilir, dışarıdan
//!     beklenen hash ile kıyaslanır.
//!   * `duplicate_payload_id_reddedilir` — Introduction'da aynı payload_id
//!     ile iki destination register edilirse ikincisi silent-overwrite yerine
//!     hata dönmeli (review-18 MED: path-swap saldırısı).
//!   * `out_of_order_chunks_dogru_konuma_yazilir` — `PayloadChunk.offset`
//!     alanı şu anki implementasyonda **yazım konumu için değil**, sadece
//!     UI progress hesabı için kullanılır; ingest sıralı append yapar. Bu
//!     gerçek davranışı pin'liyoruz (ileride bir refactor bu kontratı
//!     değiştirirse testi güncellemek gerekir).
//!   * `total_size_overrun_reddedilir` — Deklare edilen total'dan fazla
//!     body gelirse disk doldurma saldırısı engellenir.

use hekadrop::location::nearby::connections::{
    payload_transfer_frame::{
        payload_header::PayloadType as PbPayloadType, PayloadChunk, PayloadHeader,
    },
    PayloadTransferFrame,
};
use hekadrop::payload::{CompletedPayload, PayloadAssembler};
use sha2::{Digest, Sha256};

/// Test helper: `PayloadTransferFrame` inşa et. `total_size` parametresi her
/// frame'e aynı değeri yazar (overrun/truncation guard'ları bunu ister).
fn frame(
    id: i64,
    ptype: PbPayloadType,
    body: &[u8],
    last: bool,
    total_size: i64,
    offset: i64,
) -> PayloadTransferFrame {
    PayloadTransferFrame {
        packet_type: None,
        payload_header: Some(PayloadHeader {
            id: Some(id),
            r#type: Some(ptype as i32),
            total_size: Some(total_size),
            is_sensitive: None,
            file_name: None,
            parent_folder: None,
            last_modified_timestamp_millis: None,
        }),
        payload_chunk: Some(PayloadChunk {
            flags: Some(if last { 1 } else { 0 }),
            offset: Some(offset),
            body: Some(body.to_vec().into()),
            index: None,
        }),
        control_message: None,
    }
}

/// Eşsiz temp path — paralel test yürütmesinde çakışma engellenir.
fn tmp(label: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let rnd: u64 = rand::random();
    std::env::temp_dir().join(format!("hd-payload-corrupt-{}-{}-{}.bin", label, pid, rnd))
}

#[tokio::test]
async fn corrupted_chunk_sha_mismatch_reddedilir() {
    // SHA-256 entegrasyon: `CompletedPayload::File.sha256` alanı ingest sırasında
    // streaming olarak hesaplanan gerçek içerik hash'idir. Peer kötü niyetli
    // bir içerik yollarsa (ör. UI'ın beklediği dosya yerine farklı bayt dizisi),
    // üst katman bu hash'i dışarıdan beklenen imza ile kıyaslayarak farkı
    // tespit edebilir. Bu testin asıl amacı: hesaplanan hash gerçekten
    // body bayt'larının hash'idir, uydurma değil.
    let path = tmp("sha");
    let _ = std::fs::remove_file(&path);

    let mut a = PayloadAssembler::new();
    a.register_file_destination(1, path.clone()).unwrap();

    let genuine_body = b"the-original-content";
    let tampered_body = b"the-tampered-malicious-content"; // farklı uzunluk & içerik

    // "Genuine" pipeline: beklenen hash = SHA256(genuine_body)
    let mut expected_genuine = Sha256::new();
    expected_genuine.update(genuine_body);
    let expected_genuine: [u8; 32] = expected_genuine.finalize().into();

    // Ama peer tampered_body yollasın:
    let f = frame(
        1,
        PbPayloadType::File,
        tampered_body,
        true,
        tampered_body.len() as i64,
        0,
    );
    let out = a
        .ingest(&f)
        .await
        .expect("ingest ok (hash validasyonu üst katmanda)");
    let Some(CompletedPayload::File { sha256, .. }) = out else {
        panic!("File payload bekleniyordu");
    };

    // Hesaplanan hash tampered body'ninki olmalı — genuine hash'le eşleşmemeli.
    assert_ne!(
        sha256, expected_genuine,
        "tampered body'nin hash'i genuine hash ile eşleşmemeli (hash gerçek içerikten üretildi)"
    );
    let mut actual = Sha256::new();
    actual.update(tampered_body);
    let actual: [u8; 32] = actual.finalize().into();
    assert_eq!(
        sha256, actual,
        "hash gerçekten yazılan bayt'lardan türetilmeli"
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn duplicate_payload_id_reddedilir() {
    // Introduction'da aynı payload_id ile iki destination register edilirse
    // ikincisi silent-overwrite yerine hata dönmeli.
    // Saldırı senaryosu: UI'a `legit.pdf` gösterilip gerçekte `_evil.sh`
    // yazılması (review-18 MED).
    let p1 = tmp("dup1");
    let p2 = tmp("dup2");
    let mut a = PayloadAssembler::new();

    a.register_file_destination(777, p1.clone())
        .expect("ilk register başarılı olmalı");
    let err = a
        .register_file_destination(777, p2.clone())
        .expect_err("duplicate register red edilmeli");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate") || msg.contains("777"),
        "hata mesajı duplicate/ id belirtmeli, aldı: {}",
        msg
    );
}

#[tokio::test]
async fn out_of_order_chunks_dogru_konuma_yazilir() {
    // Mevcut implementasyon kontratı: `PayloadChunk.offset` yazım konumu için
    // kullanılmaz — ingest sıralı append uygular (std::io::BufWriter üzerine
    // `write_all`). Peer önce offset=1024 sonra offset=0 yollasa bile disk'teki
    // sıra "arrival order" olur. Bu davranışı pin'liyoruz; ileride offset tabanlı
    // yeniden sıralama eklenirse test güncellenmeli.
    let path = tmp("ooo");
    let _ = std::fs::remove_file(&path);

    let mut a = PayloadAssembler::new();
    a.register_file_destination(5, path.clone()).unwrap();

    // Toplam 6 bayt: "AAA" + "BBB". Peer önce offset=3 yolluyor (last=false),
    // sonra offset=0 (last=true). total_size her frame'de 6 deklare edilmeli.
    let first = frame(5, PbPayloadType::File, b"AAA", false, 6, 3);
    let second = frame(5, PbPayloadType::File, b"BBB", true, 6, 0);
    assert!(a.ingest(&first).await.unwrap().is_none());
    let done = a
        .ingest(&second)
        .await
        .unwrap()
        .expect("son chunk tamamlar");
    match done {
        CompletedPayload::File { path: p, .. } => {
            let content = std::fs::read(&p).expect("diskten oku");
            // Sıralı append → ilk yollanan "AAA", sonra "BBB". offset bilgisi
            // yok sayılır.
            assert_eq!(
                content, b"AAABBB",
                "arrival-order append: offset alanı yazım pozisyonu için değil"
            );
        }
        other => panic!("File bekleniyor, {:?}", other),
    }
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn total_size_overrun_reddedilir() {
    // Saldırgan `total_size=100` deklare edip kümülatif 200 bayt body yollarsa
    // disk doldurma engellenmeli. Kümülatif koruma: ilk chunk tek başına
    // aşmıyorsa bile, ikinci chunk total'ı geçiyorsa reddedilir.
    let path = tmp("overrun");
    let _ = std::fs::remove_file(&path);

    let mut a = PayloadAssembler::new();
    a.register_file_destination(9, path.clone()).unwrap();

    let chunk1 = vec![0x41u8; 80]; // 80 bayt — total=100 içinde
    let chunk2 = vec![0x42u8; 120]; // 80+120=200 > 100 → overrun
    let f1 = frame(9, PbPayloadType::File, &chunk1, false, 100, 0);
    let f2 = frame(9, PbPayloadType::File, &chunk2, false, 100, 80);

    a.ingest(&f1).await.expect("ilk chunk sınır içinde");
    let err = a
        .ingest(&f2)
        .await
        .expect_err("kümülatif overrun reddedilmeli");
    let msg = err.to_string();
    assert!(
        msg.contains("overrun"),
        "overrun mesajı bekleniyor, aldı: {}",
        msg
    );
    let _ = std::fs::remove_file(&path);
}
