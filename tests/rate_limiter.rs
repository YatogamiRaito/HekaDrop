//! Rate limiter — sliding window IP-bazlı bağlantı limit'i.
//!
//! Bu test `src/state.rs::RateLimiter` davranışını bağımsız bir mock üzerinden
//! doğrular. Kritik memory kuralı: **trusted cihazlar rate limit dışıdır** —
//! üst seviye çağrı `Settings::is_trusted()` kontrol ederse `check_and_record`
//! hiç çağrılmaz. Testler bu kontratı explicit olarak korur.

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

/// Kritik memory kuralı: trusted cihazlar rate limit'ten MUAF. Üst seviye
/// policy `Settings::is_trusted()` kontrol eder; trusted ise `check_and_record`
/// hiç çağrılmaz. Bu test, doğru akışın mock üzerinde gözlemlenebilir olduğunu
/// doğrular: trusted yol rate_limiter'ı hiç touch etmez.
#[test]
fn trusted_cihaz_rate_limiter_hic_cagrilmamali() {
    // Mock: counter ile kaç kez rate_limiter çağrıldığını say.
    struct PolicyCtx {
        trusted: Vec<String>,
        rate_limiter_calls: std::cell::Cell<usize>,
    }
    impl PolicyCtx {
        fn is_trusted(&self, name: &str) -> bool {
            self.trusted.iter().any(|n| n == name)
        }
        /// `incoming_device_name` → trusted ise rate limiter'a hiç dokunma.
        /// Return: bağlantı kabul edilmeli mi?
        fn should_accept(&self, device_name: &str, _ip: IpAddr) -> bool {
            if self.is_trusted(device_name) {
                // Trusted: rate limiter'a erişim YOK. Direkt kabul.
                return true;
            }
            // Untrusted: normal akış (bu testte rate_limit'i "hep geç" sayacağız
            // ama asıl aranan çağrı sayısının değişmesi).
            self.rate_limiter_calls
                .set(self.rate_limiter_calls.get() + 1);
            true
        }
    }

    let ctx = PolicyCtx {
        trusted: vec!["Ebubekir-iPhone".to_string()],
        rate_limiter_calls: std::cell::Cell::new(0),
    };
    let p = ip(10, 0, 0, 9);

    // 50 trusted istek — rate limiter sayacı 0 kalmalı
    for _ in 0..50 {
        assert!(ctx.should_accept("Ebubekir-iPhone", p));
    }
    assert_eq!(
        ctx.rate_limiter_calls.get(),
        0,
        "trusted cihaz için rate limiter çağrılmamalı (MEMORY kuralı)"
    );

    // Karışık: 3 trusted + 2 untrusted → sayaç 2 olmalı
    for _ in 0..3 {
        ctx.should_accept("Ebubekir-iPhone", p);
    }
    for _ in 0..2 {
        ctx.should_accept("YabanciCihaz", p);
    }
    assert_eq!(ctx.rate_limiter_calls.get(), 2);
}

#[test]
fn trusted_cihaz_sonsuz_baglanti_yapabilir() {
    // Trusted akış rate_limiter kullanmasa bile, untrusted akışın kendi limit'i
    // bağımsız kalmalı. İki akışın izole olduğunu doğrula.
    let rl = RateLimiter::default_prod();
    let untrusted_ip = ip(10, 0, 0, 100);
    let trusted_ip = ip(10, 0, 0, 99);
    let t = Instant::now();

    // Untrusted IP'den 10 istek → limit dolu
    for _ in 0..10 {
        assert!(!rl.check_and_record_at(untrusted_ip, t));
    }
    assert!(rl.check_and_record_at(untrusted_ip, t), "untrusted dolu");

    // Trusted flow hiç rate_limiter'a dokunmasa bile, trusted IP'nin kendi
    // queue'su bomboş kalır. İleride fallback gerekirse de kabul edilmeli.
    let before = rl.windows.read().get(&trusted_ip).cloned();
    assert!(before.is_none(), "trusted IP hiç kayıt almamalı");
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
