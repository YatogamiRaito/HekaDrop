//! H#1 — Per-transfer `CancellationToken` semantiği.
//!
//! HekaDrop binary-only (sadece `crypto` lib'de export edilir); `state`
//! modülünü test için dışarı açmıyoruz. Refactor'ın çekirdek davranışı
//! `tokio_util::sync::CancellationToken`'ın "root → child" ağacına dayanıyor —
//! regresyonu önlemek için testimiz aynı primitif üzerinde aynı ağacı kurup
//! şu üç invariant'ı doğrular:
//!
//!   1) Tek bir child token cancel → yalnız o transfer biter, kardeş
//!      transferler koşmaya devam eder (eski `AtomicBool`'da yoktu).
//!   2) Root cancel → tüm child transferler birlikte biter
//!      (`request_cancel_all()` semantiği).
//!   3) Root kardeş transferler arasında paylaşılıyor → biri
//!      `unregister/drop` olduğunda diğerinin child'ı canlı kalmalı
//!      (global flag sıfırlama bug'ı regresyon testi).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Sahte bir transfer loop'u — periyodik "iş yapıyormuş gibi" davranır; token
/// cancel'lenince en geç bir sonraki `select` turunda çıkar. Çıkış sebebi
/// boolean'ı (`true = cancelled`) çağırana geri döner.
async fn simulate_transfer(token: CancellationToken, ticks: Arc<AtomicUsize>) -> bool {
    loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => return true,
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                ticks.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[tokio::test]
async fn cancelling_one_child_does_not_affect_sibling() {
    let root = CancellationToken::new();
    let a = root.child_token();
    let b = root.child_token();

    let ticks_a = Arc::new(AtomicUsize::new(0));
    let ticks_b = Arc::new(AtomicUsize::new(0));
    let h_a = tokio::spawn(simulate_transfer(a.clone(), ticks_a.clone()));
    let h_b = tokio::spawn(simulate_transfer(b.clone(), ticks_b.clone()));

    tokio::time::sleep(Duration::from_millis(30)).await;
    a.cancel();

    let cancelled_a = tokio::time::timeout(Duration::from_millis(200), h_a)
        .await
        .expect("a task bitmeli")
        .unwrap();
    assert!(cancelled_a, "A token'ı cancel edildi → task true dönmeli");

    assert!(
        !b.is_cancelled(),
        "sibling token kardeşin cancel'ından etkilenmemeli"
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    b.cancel();
    let cancelled_b = tokio::time::timeout(Duration::from_millis(200), h_b)
        .await
        .expect("b task bitmeli")
        .unwrap();
    assert!(cancelled_b);

    assert!(
        ticks_b.load(Ordering::SeqCst) > 0,
        "B en az bir tick işlemeli"
    );
}

#[tokio::test]
async fn cancelling_root_cascades_to_all_children() {
    let root = CancellationToken::new();
    let a = root.child_token();
    let b = root.child_token();
    let c = root.child_token();

    let ticks = Arc::new(AtomicUsize::new(0));
    let ha = tokio::spawn(simulate_transfer(a, ticks.clone()));
    let hb = tokio::spawn(simulate_transfer(b, ticks.clone()));
    let hc = tokio::spawn(simulate_transfer(c, ticks.clone()));

    tokio::time::sleep(Duration::from_millis(15)).await;
    root.cancel();

    for (name, h) in [("a", ha), ("b", hb), ("c", hc)] {
        let r = tokio::time::timeout(Duration::from_millis(200), h)
            .await
            .unwrap_or_else(|_| panic!("{} task timeout", name))
            .unwrap();
        assert!(r, "{name} root cancel'dan tetiklenmeli");
    }
}

#[tokio::test]
async fn sibling_survives_after_one_transfer_drops_its_token() {
    // Regresyon (H#1): eski `AtomicBool` tasarımında `cleanup_transfer_state()`
    // flag'i sıfırlıyordu → bir transfer biterken UI'dan gelen cancel diğerine
    // ulaşmıyordu. Yeni tasarımda "bir transfer bitti" olayı sadece onun child
    // token'ının drop'u demek; kardeşin child'ı root ile canlı kalmalı.
    let root = CancellationToken::new();
    let a = root.child_token();
    let b = root.child_token();

    // A transferi biter ve token drop edilir — bu, `TransferGuard::drop` veya
    // `unregister_transfer` akışını taklit eder.
    drop(a);

    // B hâlâ root'a bağlı → root cancel hâlâ B'yi tetiklemeli.
    let ticks = Arc::new(AtomicUsize::new(0));
    let h = tokio::spawn(simulate_transfer(b, ticks));

    tokio::time::sleep(Duration::from_millis(10)).await;
    root.cancel();

    let r = tokio::time::timeout(Duration::from_millis(200), h)
        .await
        .expect("b task bitmeli")
        .unwrap();
    assert!(
        r,
        "A'nın drop'u B'yi etkilememeli, root cancel hâlâ B'ye ulaşmalı"
    );
}
