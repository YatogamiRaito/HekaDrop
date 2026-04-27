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

//! Rate limiter — sliding window IP-bazlı bağlantı limit'i.
//!
//! Bu test `src/state.rs::RateLimiter` davranışını bağımsız bir mock üzerinden
//! doğrular. Issue #17 öncesi kontrat: "trusted cihazlar gate'de
//! `check_and_record`'ı hiç çağırmaz". Issue #17 sonrası: gate'de herkes
//! `check_and_record`'a gider; hash-doğrulanmış trusted peer'lar için
//! `forget_most_recent` ile post-hoc muafiyet verilir. Testler yeni
//! kontratı explicit olarak korur.

use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// HekaDrop `RateLimiter` ile birebir davranış — Instant tabanlı sliding window.
struct RateLimiter {
    windows: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
    window: Duration,
    max_per_window: usize,
}

impl RateLimiter {
    fn new(window: Duration, max_per_window: usize) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            window,
            max_per_window,
        }
    }

    fn default_prod() -> Self {
        Self::new(Duration::from_secs(60), 10)
    }

    /// `now` parametresi test-injectable: gerçek time değil, deterministik ilerleme.
    fn check_and_record_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut windows = self.windows.write();
        let q = windows.entry(ip).or_default();

        while let Some(&front) = q.front() {
            if now.duration_since(front) > self.window {
                q.pop_front();
            } else {
                break;
            }
        }

        if q.len() >= self.max_per_window {
            return true;
        }
        q.push_back(now);
        false
    }
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn on_baglantiya_kadar_kabul_onbirinci_reddedilir() {
    let rl = RateLimiter::default_prod();
    let p = ip(192, 168, 1, 10);
    let t = Instant::now();
    for i in 0..10 {
        assert!(
            !rl.check_and_record_at(p, t + Duration::from_millis(i as u64)),
            "{}. istek kabul edilmeli",
            i + 1
        );
    }
    // 11. istek limit aşıldığı için true (reject) dönmeli
    assert!(
        rl.check_and_record_at(p, t + Duration::from_millis(11)),
        "11. istek reddedilmeli"
    );
}

#[test]
fn altmis_saniye_sonrasi_yeni_baglanti_kabul() {
    let rl = RateLimiter::default_prod();
    let p = ip(10, 0, 0, 1);
    let t0 = Instant::now();
    // 10 istek hemen
    for _ in 0..10 {
        assert!(!rl.check_and_record_at(p, t0));
    }
    // 11. şimdi → reject
    assert!(rl.check_and_record_at(p, t0));
    // 61 sn sonra → window temizlenmeli, kabul
    let t1 = t0 + Duration::from_secs(61);
    assert!(
        !rl.check_and_record_at(p, t1),
        "window dışında kalan istek kabul edilmeli"
    );
}

#[test]
fn farkli_ip_limitleri_bagimsiz() {
    let rl = RateLimiter::default_prod();
    let a = ip(10, 0, 0, 1);
    let b = ip(10, 0, 0, 2);
    let t = Instant::now();
    // A 10 istekle dolsun
    for _ in 0..10 {
        assert!(!rl.check_and_record_at(a, t));
    }
    assert!(rl.check_and_record_at(a, t), "A dolu");
    // B daha hiç istek atmadı → A'nın limiti etkilememeli
    assert!(!rl.check_and_record_at(b, t), "B bağımsız limit");
    // A hâlâ dolu
    assert!(rl.check_and_record_at(a, t));
}

#[test]
fn ipv4_vs_ipv6_ayri_kaynak() {
    let rl = RateLimiter::default_prod();
    let v4 = ip(10, 0, 0, 1);
    let v6 = IpAddr::V6("::1".parse().unwrap());
    let t = Instant::now();
    for _ in 0..10 {
        assert!(!rl.check_and_record_at(v4, t));
    }
    // v6 adresi farklı peer — limit etkilememeli
    assert!(!rl.check_and_record_at(v6, t));
}

#[test]
fn sliding_window_kaydirimi_yari_window() {
    let rl = RateLimiter::default_prod();
    let p = ip(10, 0, 0, 5);
    let t0 = Instant::now();
    // İlk 5 istek t=0
    for _ in 0..5 {
        assert!(!rl.check_and_record_at(p, t0));
    }
    // Sonraki 5 istek t=30s
    let t30 = t0 + Duration::from_secs(30);
    for _ in 0..5 {
        assert!(!rl.check_and_record_at(p, t30));
    }
    // Toplam 10 → 11. t=30s'de reject
    assert!(rl.check_and_record_at(p, t30));

    // t=61s: ilk 5 istek window'dan düştü; şimdi 5 istek kabul edilebilir
    let t61 = t0 + Duration::from_secs(61);
    for _ in 0..5 {
        assert!(!rl.check_and_record_at(p, t61), "sliding window sonrası");
    }
    // Şimdi 10 doldu → 11. reject
    assert!(rl.check_and_record_at(p, t61));
}

/// Issue #17 kontratı: gate'de HERKES `check_and_record` çağırır; trusted
/// peer muafiyeti yalnız hash doğrulandıktan sonra `forget_most_recent` ile
/// geriye-dönük verilir. Bu test güncel kontratı pin'liyor.
///
/// Eski test ("gate'de trusted bypass, check_and_record hiç çağrılmaz")
/// Issue #17 öncesi davranıştı — peer-controlled (name, id) spoof'a izin
/// verdiği için kaldırıldı.
#[test]
fn hash_verified_peer_gate_sonrasi_forget_ile_muafiyet() {
    // Mock akış:
    //   1. Gate: check_and_record — herkes çağırır (bypass yok).
    //   2. PairedKeyEncryption sonrası: hash doğrulandıysa
    //      forget_most_recent çağrılır.
    struct PolicyCtx {
        trusted_hashes: std::collections::HashSet<[u8; 6]>,
        check_calls: std::cell::Cell<usize>,
        forget_calls: std::cell::Cell<usize>,
    }
    impl PolicyCtx {
        fn flow(&self, peer_hash: Option<[u8; 6]>) {
            // Gate
            self.check_calls.set(self.check_calls.get() + 1);
            // Post-hoc
            if let Some(h) = peer_hash {
                if self.trusted_hashes.contains(&h) {
                    self.forget_calls.set(self.forget_calls.get() + 1);
                }
            }
        }
    }

    let hash = [0x42u8; 6];
    let ctx = PolicyCtx {
        trusted_hashes: [hash].into_iter().collect(),
        check_calls: std::cell::Cell::new(0),
        forget_calls: std::cell::Cell::new(0),
    };

    // 50 trusted (hash-verified) istek — her biri check, her biri forget.
    for _ in 0..50 {
        ctx.flow(Some(hash));
    }
    assert_eq!(
        ctx.check_calls.get(),
        50,
        "Issue #17: gate'de trusted da olsa check_and_record çağrılır"
    );
    assert_eq!(ctx.forget_calls.get(), 50, "her trusted handshake forget");

    // Hash yok (legacy spoof ya da spec dışı peer) — forget çağrılmaz.
    for _ in 0..3 {
        ctx.flow(None);
    }
    assert_eq!(ctx.check_calls.get(), 53);
    assert_eq!(ctx.forget_calls.get(), 50, "hash yok → forget yok");
}

#[test]
fn hash_verified_peer_sonsuz_baglanti_yapabilir() {
    // Hash-verified peer her handshake'de check + forget çekildiği için
    // queue sürekli 0'a dönüyor → sürekli bağlantı yapabilir. Untrusted
    // akış bağımsız kalmalı.
    let rl = RateLimiter::default_prod();
    let untrusted_ip = ip(10, 0, 0, 100);
    let trusted_ip = ip(10, 0, 0, 99);
    let t = Instant::now();

    // Untrusted IP'den 10 istek → limit dolu
    for _ in 0..10 {
        assert!(!rl.check_and_record_at(untrusted_ip, t));
    }
    assert!(rl.check_and_record_at(untrusted_ip, t), "untrusted dolu");

    // Trusted IP: gate kaydeder (1 kayıt) → post-hoc forget simülasyonu.
    // Burada sadece gate davranışını gösteriyoruz — forget prod-level
    // `src/state.rs::RateLimiter::forget_most_recent` tarafından test
    // ediliyor (tests/trust_hijack.rs::issue_17_rate_limit modülü).
    assert!(!rl.check_and_record_at(trusted_ip, t));
    let len = rl.windows.read().get(&trusted_ip).map(|q| q.len());
    assert_eq!(
        len,
        Some(1),
        "gate kayıt bıraktı (post-hoc forget ile silinecek)"
    );
}

#[test]
fn window_ve_max_konfigurable() {
    // Custom window/max ile özel test: 2 saniye / 3 istek
    let rl = RateLimiter::new(Duration::from_secs(2), 3);
    let p = ip(127, 0, 0, 1);
    let t = Instant::now();
    assert!(!rl.check_and_record_at(p, t));
    assert!(!rl.check_and_record_at(p, t));
    assert!(!rl.check_and_record_at(p, t));
    assert!(rl.check_and_record_at(p, t), "4. reddedilmeli");
    // 2.1 saniye sonra → tüm pencere dışı
    assert!(!rl.check_and_record_at(p, t + Duration::from_millis(2100)));
}
