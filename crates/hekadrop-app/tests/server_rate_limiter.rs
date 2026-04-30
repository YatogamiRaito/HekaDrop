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

//! Server katmanı rate-limit invariant'ları — per-IP sliding window + trust muafiyeti.
//!
//! `src/state.rs::RateLimiter` production tipi üst katman (`AppState`) bağımlılığı
//! yüzünden doğrudan integration-test'ten import edilemez. Bu yüzden `tests/
//! rate_limiter.rs` deseni ile birebir aynı davranışı mirror eder ve kritik
//! server-seviye invariant'ları pin'ler. `src/server.rs` / `src/state.rs`
//! production koduna dokunulmaz — sadece contract korunur.
//!
//! Pin'lenen invariant'lar:
//!   * `untrusted_ip_11_conn_reddedilir` — 60sn penceresinde 10 bağlantı
//!     sonrasında aynı IP'den 11. bağlantı reddedilir.
//!   * `trusted_ip_rate_limit_bypass` — **Hash-doğrulanmış** trusted peer'lar
//!     rate limit'ten post-hoc muaftır (Issue #17 closure). Eskiden
//!     gate'de `(name, id)` üzerinden muafiyet verilirdi; artık
//!     `PairedKeyEncryption` sonrası hash doğrulandığında
//!     `forget_most_recent` ile kayıt geri alınır. Gate peer-controlled
//!     string'lere güvenmez.
//!   * `farkli_ip_bagimsiz_pencere` — Farklı IP'ler birbirinin limit
//!     penceresini etkilememeli (`HashMap` key=IpAddr).
//!   * `spoofed_legacy_name_id_rate_limit_bypass_yapmamali` —
//!     Issue #17: gate'de legacy (name, id) muafiyeti YOK.
//!   * `hash_dogrulanmadan_muafiyet_verilmez` — Hash yoksa queue intact.

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
    // Issue #17: gate'de muafiyet artık peer-controlled string'e değil,
    // hash-doğrulanmış kanıta bağlı. Mock burada production akışını
    // simüle ediyor:
    //   1. Gate'de HERKES `check_and_record` çağırır (bypass yok).
    //   2. PairedKeyEncryption frame'i sonrası hash doğrulanırsa
    //      `forget_most_recent` ile kayıt geri alınır (post-hoc muafiyet).
    //
    // Eski test "gate'de bypass" kontratını pin'liyordu — o semantik
    // Issue #17 ile kaldırıldı. Yeni kontrat: hash-verified peer sürekli
    // bağlantı yapabilir ama her gate geçişi önce kaydedilir, sonra silinir.
    struct PolicyCtx {
        trusted_hashes: std::collections::HashSet<[u8; 6]>,
        rate_limiter_calls: std::cell::Cell<usize>,
        forget_calls: std::cell::Cell<usize>,
    }
    impl PolicyCtx {
        fn is_trusted_by_hash(&self, h: &[u8; 6]) -> bool {
            self.trusted_hashes.contains(h)
        }
        /// Production ile aynı sıralama: gate'de `check_and_record`, sonra
        /// `PairedKeyEncryption` frame'i sonrası hash doğrulanırsa forget.
        fn accept_flow(&self, peer_hash: Option<[u8; 6]>) -> bool {
            // 1) Gate: herkes rate-limit'e tabi.
            self.rate_limiter_calls
                .set(self.rate_limiter_calls.get() + 1);
            // 2) PairedKeyEncryption sonrası post-hoc muafiyet.
            if let Some(h) = peer_hash {
                if self.is_trusted_by_hash(&h) {
                    self.forget_calls.set(self.forget_calls.get() + 1);
                }
            }
            true
        }
    }

    let trusted_hash = [0xAAu8; 6];
    let ctx = PolicyCtx {
        trusted_hashes: [trusted_hash].into_iter().collect(),
        rate_limiter_calls: std::cell::Cell::new(0),
        forget_calls: std::cell::Cell::new(0),
    };

    // Trusted (hash-verified) cihazdan 100 bağlantı → her biri rate-limit
    // sayacına değer ama her biri post-hoc forget ile geri alınır.
    for _ in 0..100 {
        assert!(ctx.accept_flow(Some(trusted_hash)));
    }
    assert_eq!(
        ctx.rate_limiter_calls.get(),
        100,
        "Issue #17: trusted da olsa gate'de check_and_record çağrılır"
    );
    assert_eq!(
        ctx.forget_calls.get(),
        100,
        "hash doğrulandığında her seferinde forget_most_recent çağrılır"
    );

    // Stranger (hash=None, legacy spoof değil) — forget çağrılmaz.
    for _ in 0..3 {
        ctx.accept_flow(None);
    }
    assert_eq!(ctx.rate_limiter_calls.get(), 103);
    assert_eq!(
        ctx.forget_calls.get(),
        100,
        "hash yok → forget çağrılmamalı (kayıt intact)"
    );

    // Attacker (hash sahip ama trusted değil) — forget çağrılmaz.
    let attacker_hash = [0xBBu8; 6];
    for _ in 0..5 {
        ctx.accept_flow(Some(attacker_hash));
    }
    assert_eq!(ctx.rate_limiter_calls.get(), 108);
    assert_eq!(
        ctx.forget_calls.get(),
        100,
        "trusted olmayan hash → forget çağrılmamalı"
    );
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

// ===== Issue #17 — gate'de spoofed legacy bypass yok =====

/// Issue #17: `connection.rs` gate'inde `is_trusted_legacy(name, id)` artık
/// rate-limit muafiyeti vermiyor. Saldırgan kurbanın trusted listesindeki
/// `(name, id)` çiftini spoof etse bile `check_and_record` her bağlantıda
/// çağrılır. Bu test eski davranışı (gate'de muafiyet) kıran düzeltmeyi
/// pin'ler — policy mock'u "trusted kayıt var ama gate muafiyet yok"
/// akışını simüle eder.
#[test]
fn spoofed_legacy_name_id_rate_limit_bypass_yapmamali() {
    // Policy: "trusted listede (name, id) var, ama gate'de muafiyet YOK".
    // Her bağlantı rate_limiter.check_and_record'a gidecek.
    struct PolicyCtx {
        _trusted_legacy: Vec<(String, String)>, // bağlamsal — artık gate'e etki etmiyor
        rate_limiter: RateLimiter,
    }
    impl PolicyCtx {
        fn accept(&self, _name: &str, _id: &str, ip: IpAddr, now: Instant) -> bool {
            // Issue #17: legacy check gate'den kaldırıldı → herkes rate-limit'e tabi.
            !self.rate_limiter.check_and_record_at(ip, now)
        }
    }

    let ctx = PolicyCtx {
        _trusted_legacy: vec![("iPhone".into(), "ABCD".into())],
        rate_limiter: RateLimiter::prod(),
    };
    let ip = ipv4(198, 51, 100, 9);
    let t0 = Instant::now();

    // Saldırgan "iPhone"/"ABCD" spoof'u → 10 bağlantı kabul.
    for i in 0..10 {
        let ok = ctx.accept("iPhone", "ABCD", ip, t0 + Duration::from_millis(i));
        assert!(ok, "{}. spoofed bağlantı cap altında kabul", i + 1);
    }
    // 11. bağlantı: spoof'a rağmen cap dolu → reject.
    let ok_11 = ctx.accept("iPhone", "ABCD", ip, t0 + Duration::from_millis(10));
    assert!(
        !ok_11,
        "Issue #17: spoofed (name, id) rate-limit bypass YAPMAMALI"
    );
}

/// Hash doğrulanmadığı sürece rate-limit sayacı intact kalmalı. Production
/// `connection.rs` flow'u: `if let Some(h) = *peer_secret_id_hash { if
/// is_trusted_by_hash(&h) { forget_most_recent(...) } }` — hash yoksa veya
/// trusted değilse forget çağrılmaz.
#[test]
fn hash_dogrulanmadan_muafiyet_verilmez() {
    let rl = RateLimiter::prod();
    let ip = ipv4(203, 0, 113, 15);
    let t = Instant::now();

    for _ in 0..5 {
        assert!(!rl.check_and_record_at(ip, t));
    }
    // Hash yok → forget_most_recent çağrılmıyor. Queue 5 kayıtlı kalmalı.
    // (Mirror'daki RateLimiter'da forget_most_recent direct erişim yok;
    // production side ile aynı davranış: çağrı yoksa queue değişmez.)
    let queue_len = rl
        .windows
        .read()
        .get(&ip)
        .map_or(0, std::collections::VecDeque::len);
    assert_eq!(
        queue_len, 5,
        "hash doğrulanmadığında queue intact kalmalı (forget_most_recent çağrılmaz)"
    );

    // Devamında 5 daha → toplam 10 → 11. reject.
    for _ in 0..5 {
        assert!(!rl.check_and_record_at(ip, t));
    }
    assert!(
        rl.check_and_record_at(ip, t),
        "11. bağlantı cap'i aştığı için reject — hash doğrulanmamış peer muafiyet almaz"
    );
}
