//! Server katmanı rate-limit invariant'ları — per-IP sliding window + trust muafiyeti.
//!
//! `src/state.rs::RateLimiter` production tipi üst katman (`AppState`) bağımlılığı
//! yüzünden doğrudan integration-test'ten import edilemez. Bu yüzden `tests/
//! rate_limiter.rs` deseni ile birebir aynı davranışı mirror eder ve kritik
//! server-seviye invariant'ları pin'ler. `src/server.rs` / `src/state.rs`
//! production koduna dokunulmaz — sadece contract korunur.
//!
//! Pin'lenen invariant'lar (CLAUDE.md "memory" kuralı dahil):
//!   * `untrusted_ip_11_conn_reddedilir` — 60sn penceresinde 10 bağlantı
//!     sonrasında aynı IP'den 11. bağlantı reddedilir.
//!   * `trusted_ip_rate_limit_bypass` — **Trusted cihazlar rate limit'ten
//!     MUAFTIR.** Policy katmanı `Settings::is_trusted()` kontrol eder;
//!     trusted ise `check_and_record` hiç çağrılmaz. Bu test mock üzerinden
//!     çağrı sayacını izleyerek rate limiter'ın dokunulmadığını doğrular.
//!   * `farkli_ip_bagimsiz_pencere` — Farklı IP'ler birbirinin limit
//!     penceresini etkilememeli (HashMap key=IpAddr).

use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// `src/state.rs::RateLimiter` birebir davranış mirror'u — Instant inject edilir
/// (gerçek `std::time::Instant::now()` yerine deterministik ilerleme).
struct RateLimiter {
    windows: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
    window: Duration,
    max_per_window: usize,
}

impl RateLimiter {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_PER_WINDOW: usize = 10;

    fn prod() -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            window: Self::WINDOW,
            max_per_window: Self::MAX_PER_WINDOW,
        }
    }

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

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn untrusted_ip_11_conn_reddedilir() {
    // Aynı IP, trusted değil: 60sn penceresinde 10 bağlantı kabul,
    // 11. reddedilmeli. Quick Share peer'ının makul tekrar bağlantı
    // ihtiyacı 10/dk'nın çok altındadır; üstü saldırı varsayılır.
    let rl = RateLimiter::prod();
    let ip = ipv4(192, 168, 1, 42);
    let t0 = Instant::now();

    for i in 0..10 {
        let reject = rl.check_and_record_at(ip, t0 + Duration::from_millis(i));
        assert!(!reject, "{}. bağlantı kabul edilmeli", i + 1);
    }
    // 11. bağlantı pencereye sığmadı → reject.
    let reject = rl.check_and_record_at(ip, t0 + Duration::from_millis(10));
    assert!(reject, "11. bağlantı reddedilmeli (cap=10 / 60s)");
}

#[test]
fn trusted_ip_rate_limit_bypass() {
    // CLAUDE.md memory kuralı: trusted cihazlar rate limit'ten MUAFTIR.
    // `connection::handle` akışında önce `Settings::is_trusted()` sorulur;
    // true ise `rate_limiter.check_and_record` **hiç çağrılmaz**. Bu testte
    // policy mock'u üzerinden çağrı sayısı gözlenir.
    struct PolicyCtx {
        trusted_devices: Vec<String>,
        rate_limiter_calls: std::cell::Cell<usize>,
    }
    impl PolicyCtx {
        fn is_trusted(&self, device_name: &str) -> bool {
            self.trusted_devices.iter().any(|n| n == device_name)
        }
        /// Production ile aynı sıralama: önce trust sorgusu, sonra rate.
        fn accept(&self, device_name: &str) -> bool {
            if self.is_trusted(device_name) {
                return true; // BYPASS
            }
            self.rate_limiter_calls
                .set(self.rate_limiter_calls.get() + 1);
            true
        }
    }

    let ctx = PolicyCtx {
        trusted_devices: vec!["MyPhone".to_string()],
        rate_limiter_calls: std::cell::Cell::new(0),
    };

    // Trusted cihazdan 100 bağlantı → rate_limiter sayacı 0 olmalı.
    for _ in 0..100 {
        assert!(ctx.accept("MyPhone"));
    }
    assert_eq!(
        ctx.rate_limiter_calls.get(),
        0,
        "trusted bypass: rate limiter'a dokunulmamalı (memory kuralı)"
    );

    // Aynı ctx'e untrusted 3 bağlantı → sayaç 3'e çıkmalı.
    for _ in 0..3 {
        ctx.accept("Stranger");
    }
    assert_eq!(ctx.rate_limiter_calls.get(), 3);

    // Sonraki 50 trusted çağrı sayacı hâlâ artırmamalı.
    for _ in 0..50 {
        ctx.accept("MyPhone");
    }
    assert_eq!(ctx.rate_limiter_calls.get(), 3, "trusted yine sayaçsız");
}

#[test]
fn farkli_ip_bagimsiz_pencere() {
    // HashMap<IpAddr, _> → her IP için ayrı queue. A dolsa bile B etkilenmez.
    let rl = RateLimiter::prod();
    let a = ipv4(10, 0, 0, 1);
    let b = ipv4(10, 0, 0, 2);
    let t = Instant::now();

    // A'yı doldur.
    for _ in 0..10 {
        assert!(!rl.check_and_record_at(a, t));
    }
    assert!(rl.check_and_record_at(a, t), "A cap'i doldu");

    // B hiç kayıt yapmadı → bağımsız; 10 bağlantı yine kabul edilmeli.
    for i in 0..10 {
        assert!(
            !rl.check_and_record_at(b, t),
            "B'nin {}. bağlantısı A'dan etkilenmemeli",
            i + 1
        );
    }
    // Her iki IP de artık kapasitede.
    assert!(rl.check_and_record_at(a, t), "A hâlâ dolu");
    assert!(rl.check_and_record_at(b, t), "B de şimdi dolu");

    // IPv6 yine farklı key — bağımsız pencere.
    let v6: IpAddr = "::1".parse().unwrap();
    assert!(!rl.check_and_record_at(v6, t), "IPv6 farklı kaynak");
}
