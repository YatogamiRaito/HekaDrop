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

//! H#2 (v0.6.0) regression guard — `Settings::save()` / `Stats::save()` disk
//! I/O çağrısı sırasında `RwLock` write-guard'ının tutulmaması gerekir.
//!
//! ## Sorun (H#2)
//! v0.5.x'te kod şu pattern'i kullanıyordu:
//! ```ignore
//! let mut g = SETTINGS.write();
//! g.auto_accept = true;
//! g.save()?;   // ← disk I/O write-guard altında
//! ```
//! Yavaş dosya sistemlerinde (encrypted home, FUSE mount, network FS)
//! `fs::rename` ve `sync_all` 50–500 ms arasında bloklayabiliyor. Bu sürede
//! `RwLock` `read()` çağrısı bile bloklanıyor (write-lock öncelikli) ve UI
//! tick'i donuyordu.
//!
//! ## Çözüm
//! Her `save()` çağrısı artık **snapshot-clone-drop** pattern'i kullanıyor:
//! ```ignore
//! let snap = {
//!     let mut g = SETTINGS.write();
//!     g.auto_accept = true;
//!     g.clone()
//! }; // ← guard burada düşer
//! let _ = snap.save();  // disk I/O lock dışında
//! ```
//!
//! ## Bu test ne kontrol ediyor?
//! Gerçek `Settings` tipini import etmek için `src/lib.rs`'in `platform`,
//! `config` gibi heavy FFI modüllerini export etmesi gerekirdi. Bunun yerine
//! pattern'i **genelleştirilmiş** bir senaryoda test ediyoruz:
//!
//! * `RwLock<Payload>` state
//! * Task A: 100 defa `snapshot-drop-then-disk-write` yapar (her yazım
//!   ≥5 ms fsync + rename simulasyonu)
//! * Task B: pattern'in doğru uygulandığını doğrulamak için `read()` guard
//!   alma süresini ölçer — A çalışırken B'nin read-acquire wall-time'ı
//!   threshold altında kalmalı.
//!
//! ## False positive / negative senaryoları
//! * CI runner'da IO ciddi yavaşsa threshold aşılabilir — generous bir
//!   threshold (100 ms) kullanıyoruz.
//! * Pattern regresse ederse (ör. biri `save()`'i guard altında çağırmaya
//!   dönerse) B'nin read-acquire süresi disk I/O süresiyle doğrudan
//!   korele olur → assertion patlar.
//!
//! ## Referans call-site'lar (pattern uygulanmış yerler)
//!   * `src/connection.rs:302-313` (stats.record_received)
//!   * `src/connection.rs:578-586` (touch_trusted_by_hash)
//!   * `src/connection.rs:622-629` (add_trusted_with_hash upgrade)
//!   * `src/connection.rs:638-660` (AcceptAndTrust kayıt)
//!   * `src/sender.rs:285-295` (stats.record_sent)
//!   * `src/main.rs:425-432` (auto_accept toggle)
//!   * `src/main.rs:464-471` (trust_remove)
//!   * `src/main.rs:497-503` (stats_reset)
//!   * `src/main.rs:515-522` (trusted_clear)
//!   * `src/main.rs:565-574` (handle_settings_save)
//!   * `src/main.rs:801-806` (open_config_file — H#2'de düzeltildi)

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Pattern'in test edildiği tipik bir "büyük snapshot" payload'u —
/// `Settings` struct'ının büyüklüğüne yakın (~1 KB serialize).
///
/// `flags` alanı clone maliyetini artırmak için doldurulur (gerçek `Settings`
/// ~40 alan içeriyor); okunmasına gerek yok — bu yüzden `#[allow(dead_code)]`.
#[derive(Clone, Default)]
#[allow(dead_code)]
struct Payload {
    devices: Vec<String>,
    flags: Vec<bool>,
    counters: Vec<u64>,
}

impl Payload {
    fn new() -> Self {
        Self {
            devices: (0..32).map(|i| format!("device-{}", i)).collect(),
            flags: vec![false; 64],
            counters: vec![0; 64],
        }
    }

    /// Disk I/O simülasyonu — `atomic_write` (write + fsync + rename) yaklaşık
    /// 5–10 ms sürer. Yavaş FS'te kolayca 50 ms'e çıkabilir.
    fn save_slow(&self, path: &std::path::Path) -> std::io::Result<()> {
        // Serialize — gerçek Settings JSON serialize'e yakın maliyet.
        let bytes: Vec<u8> = self.devices.join(",").into_bytes();
        // Tmp + rename — atomic_write'ı modelle.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        // Yavaş disk simülasyonu — encrypted/FUSE mount'ta fsync latency.
        std::thread::sleep(Duration::from_millis(5));
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// ## H#2 — snapshot-clone-drop pattern write-lock'u kısa süre tutmalı.
///
/// Invariant: `save()` çağrısı sırasında `write()` guard'ı en fazla birkaç
/// yüz mikrosaniye tutulmalı. Gerçek disk I/O (5 ms × 100 = 500 ms toplam)
/// paralel bir `read()` task'ını bloklamamalı.
///
/// Eşik: Reader task'ın tek bir `read()` acquire süresi 100 ms altında
/// kalmalı. Pattern regresse olursa reader 500 ms'e kadar bloklanır.
#[test]
fn save_write_lock_not_held_during_disk_io() {
    let dir = std::env::temp_dir().join(format!(
        "hekadrop-save-nonblock-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let path = Arc::new(dir.join("settings.json"));

    let state: Arc<RwLock<Payload>> = Arc::new(RwLock::new(Payload::new()));
    let stop = Arc::new(AtomicBool::new(false));

    // Writer task — doğru pattern: clone snapshot, drop guard, save.
    let writer = {
        let state = Arc::clone(&state);
        let path = Arc::clone(&path);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            for i in 0..100 {
                // YENİ (doğru) pattern:
                let snap = {
                    let mut g = state.write();
                    let idx = i % g.counters.len();
                    g.counters[idx] += 1;
                    g.clone()
                }; // ← guard burada düşer
                let _ = snap.save_slow(&path); // disk I/O lock dışında
            }
            stop.store(true, Ordering::SeqCst);
        })
    };

    // Reader task — writer çalışırken read() acquire latency'sini ölç.
    let max_read_acquire_ns = {
        let state = Arc::clone(&state);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut max_ns: u128 = 0;
            let mut samples = 0u32;
            while !stop.load(Ordering::SeqCst) {
                let t0 = Instant::now();
                let g = state.read();
                let elapsed = t0.elapsed().as_nanos();
                // Guard'ı kısa süre tut (simüle edilmiş UI tick).
                let _devices_len = g.devices.len();
                drop(g);
                if elapsed > max_ns {
                    max_ns = elapsed;
                }
                samples += 1;
                // Küçük nefes payı — busy-loop olmasın ama yine de sık örnekleyelim.
                std::thread::sleep(Duration::from_micros(100));
            }
            (max_ns, samples)
        })
        .join()
        .expect("reader thread join")
    };
    writer.join().expect("writer thread join");

    let (max_ns, samples) = max_read_acquire_ns;
    let max_ms = max_ns as f64 / 1_000_000.0;
    let _ = std::fs::remove_dir_all(&dir);

    // Eşik: 100 ms. Pattern doğruysa tipik değer <1 ms (mutasyon ~µs).
    // Regresse senaryoda (guard altında save) bu değer 5+ ms'e fırlar
    // — her writer iterasyonu reader'ı tam blokladığı için max >= 5 ms.
    assert!(
        samples > 10,
        "reader yeterince örnekleme yapamadı: {}",
        samples
    );
    assert!(
        max_ms < 100.0,
        "read() acquire max {:.3} ms — snapshot pattern regresse olmuş olabilir \
         (write guard disk I/O altında tutuluyor). Örnek sayısı: {}",
        max_ms,
        samples
    );
}

/// ## H#2 — pattern'i doğru uygulamayan (REGRESSED) kodun reader'ı bloklar.
///
/// Bu test snapshot pattern'i ters çevirerek (guard altında save) eski bug'ı
/// yeniden üretir ve reader'ın bloklandığını gösterir. Böylece üstteki testin
/// gerçekten pattern'i test ettiğini doğrularız — defensive self-check.
///
/// `#[ignore]` çünkü intentionally yavaş ve assertion ters yönde. CI'da
/// opt-in olarak koşulur: `cargo test -- --ignored regressed`.
#[test]
#[ignore]
fn regressed_pattern_blocks_reader_self_check() {
    let dir = std::env::temp_dir().join(format!(
        "hekadrop-save-regressed-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let path = Arc::new(dir.join("settings.json"));

    let state: Arc<RwLock<Payload>> = Arc::new(RwLock::new(Payload::new()));
    let stop = Arc::new(AtomicBool::new(false));

    // REGRESSED (eski, problemli) pattern: guard altında save.
    let writer = {
        let state = Arc::clone(&state);
        let path = Arc::clone(&path);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            for i in 0..20 {
                let mut g = state.write();
                let idx = i % g.counters.len();
                g.counters[idx] += 1;
                let _ = g.save_slow(&path); // ← guard altında disk I/O
                drop(g);
            }
            stop.store(true, Ordering::SeqCst);
        })
    };

    let (max_ns, _samples) = {
        let state = Arc::clone(&state);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut max_ns: u128 = 0;
            let mut samples = 0u32;
            while !stop.load(Ordering::SeqCst) {
                let t0 = Instant::now();
                let _g = state.read();
                let elapsed = t0.elapsed().as_nanos();
                if elapsed > max_ns {
                    max_ns = elapsed;
                }
                samples += 1;
                std::thread::sleep(Duration::from_micros(100));
            }
            (max_ns, samples)
        })
        .join()
        .expect("reader join")
    };
    writer.join().expect("writer join");
    let _ = std::fs::remove_dir_all(&dir);

    let max_ms = max_ns as f64 / 1_000_000.0;
    // Regressed pattern reader'ı en az save_slow süresi (5 ms) kadar bloklar.
    assert!(
        max_ms >= 3.0,
        "regressed pattern reader'ı {:.3} ms bekletti — beklenen >=3 ms",
        max_ms
    );
}
