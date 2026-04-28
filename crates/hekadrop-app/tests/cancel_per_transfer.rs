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
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Cancel yolunun ne kadar sürede observe edildiğinin üst sınırı. CI runner
/// yavaş paralel testler altında 200 ms çok sıkıydı; 500 ms güvenlik marjı
/// verirken gerçek regresyonu yine saniyenin yarısı içinde yakalar.
const CANCEL_OBSERVE_TIMEOUT: Duration = Duration::from_millis(500);

/// Sahte bir transfer loop'u — periyodik "iş yapıyormuş gibi" davranır; token
/// cancel'lenince en geç bir sonraki `select` turunda çıkar. `started`
/// ile "task aktif select'te" sinyali verir; çağıran `started.notified()`
/// ile bunu bekleyerek time-based sleep'i elimine eder. Çıkış sebebi
/// boolean'ı (`true = cancelled`) çağırana geri döner.
async fn simulate_transfer(
    token: CancellationToken,
    ticks: Arc<AtomicUsize>,
    started: Arc<Notify>,
) -> bool {
    started.notify_one();
    loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => return true,
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
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
    let started_a = Arc::new(Notify::new());
    let started_b = Arc::new(Notify::new());
    let h_a = tokio::spawn(simulate_transfer(
        a.clone(),
        ticks_a.clone(),
        started_a.clone(),
    ));
    let h_b = tokio::spawn(simulate_transfer(
        b.clone(),
        ticks_b.clone(),
        started_b.clone(),
    ));

    // Event-based sync: sleep yerine task gerçekten select'e girene kadar bekle.
    started_a.notified().await;
    started_b.notified().await;
    a.cancel();

    let cancelled_a = tokio::time::timeout(CANCEL_OBSERVE_TIMEOUT, h_a)
        .await
        .expect("a task bitmeli")
        .unwrap();
    assert!(cancelled_a, "A token'ı cancel edildi → task true dönmeli");

    assert!(
        !b.is_cancelled(),
        "sibling token kardeşin cancel'ından etkilenmemeli"
    );

    // B'nin en az bir tick işlemesi için minimal yield — sleep cömert.
    tokio::time::sleep(Duration::from_millis(100)).await;
    b.cancel();
    let cancelled_b = tokio::time::timeout(CANCEL_OBSERVE_TIMEOUT, h_b)
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
    let s_a = Arc::new(Notify::new());
    let s_b = Arc::new(Notify::new());
    let s_c = Arc::new(Notify::new());
    let ha = tokio::spawn(simulate_transfer(a, ticks.clone(), s_a.clone()));
    let hb = tokio::spawn(simulate_transfer(b, ticks.clone(), s_b.clone()));
    let hc = tokio::spawn(simulate_transfer(c, ticks.clone(), s_c.clone()));

    // Tüm task'lar aktif olana kadar bekle — `root.cancel()` öncesi garanti.
    s_a.notified().await;
    s_b.notified().await;
    s_c.notified().await;
    root.cancel();

    for (name, h) in [("a", ha), ("b", hb), ("c", hc)] {
        let r = tokio::time::timeout(CANCEL_OBSERVE_TIMEOUT, h)
            .await
            .unwrap_or_else(|_| panic!("{name} task timeout"))
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
    let started = Arc::new(Notify::new());
    let h = tokio::spawn(simulate_transfer(b, ticks, started.clone()));

    started.notified().await;
    root.cancel();

    let r = tokio::time::timeout(CANCEL_OBSERVE_TIMEOUT, h)
        .await
        .expect("b task bitmeli")
        .unwrap();
    assert!(
        r,
        "A'nın drop'u B'yi etkilememeli, root cancel hâlâ B'ye ulaşmalı"
    );
}
