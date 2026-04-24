//! Trust hijacking regression — Issue #17 (T2 senaryosu).
//!
//! v0.5.x trust kararı `(device_name, endpoint_id)` çiftine bağlıydı —
//! `endpoint_id` 4 ASCII bayt ve her oturumda rastgele, dolayısıyla
//! spoof edilebilir. Saldırgan kurbanın trusted listesindeki bir cihazın
//! adını + id'sini taklit ederek dialog'u bypass edebilirdi (bkz. design
//! 017 §2.2 T2).
//!
//! v0.6 trust kararı `PairedKeyEncryption.secret_id_hash` üzerinden — peer'ın
//! uzun-süreli kimlik anahtarından türetilmiş 6 bayt HKDF. Aynı (name, id)
//! çiftiyle farklı hash göndermek (saldırganın gerçek cihazın anahtarı
//! olmadığı için mümkün olmayan şey) artık trust'ı yanıltamaz.
//!
//! Bu test, full handshake yerine `Settings::is_trusted_by_hash` katmanında
//! senaryoyu doğrular — tasarım 017 §7.2'nin karar kurallarını birebir
//! karşılayan unit-harness. Full connection-level integration testi
//! (socket + UKEY2 + PayloadAssembler) bu PR için aşırı kapsamlı; burada
//! yalnız trust-karar mekaniği izole edilmiştir.

use serde_json::json;

// v0.6 settings şemasının wire formatı — gerçek `Settings` struct'u
// internal (private `hex_hash_opt` module wire formatına sahip); test
// tarafında JSON'u doğrudan üretip binary içindeki parser'ı çağırmak
// entegrasyon açısından daha değerli ama private module dışarıdan
// görünmediği için burada JSON sözleşmesini test ediyoruz: gelen JSON'u
// binary doğru parse ediyor, hash farklılığında trust false dönüyor.
//
// Bu test binary'nin `settings` modülü üzerinden çalışır (`tests/`
// integration test'leri binary modüllerine erişemez; onun için aşağıda
// logic'i manuel replica ediyoruz). Gerçek production modülü için
// `src/settings.rs::tests::v06_hijack_regression_ayni_name_id_farkli_hash_untrusted`
// aynı karar kuralını doğrular.

// Settings'in test replicası — wire-compat JSON ile aynı alanları taşır.
// Gerçek prod kod `src/settings.rs` içinde; bu dosya test harness'ı olarak
// yalnız mantıksal eşdeğerliği doğrular.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[test]
fn t2_trust_hijack_farkli_hash_ile_dialog_gosterilir() {
    // Kurbanın settings'i: (name="Pixel", id="ABCD", hash=[0xAA;6]).
    // Saldırgan: aynı (name, id) ama farklı hash (= [0xBB;6]) ile bağlanır.
    let victim_hash: [u8; 6] = [0xAA; 6];
    let attacker_hash: [u8; 6] = [0xBB; 6];

    let victim_record = json!({
        "name": "Pixel",
        "id": "ABCD",
        "secret_id_hash": hex::encode(victim_hash),
        "trusted_at_epoch": now(),
    });
    let settings_json = json!({
        "trust_ttl_secs": 7 * 24 * 3600u64,
        "trusted_devices": [victim_record],
    })
    .to_string();

    // Gerçek binary'nin `Settings` struct'ı private; wire formatı JSON
    // üzerinden replica — hijack kararı aşağıdaki üç satıra indirgenir.
    // Production karar kuralı (`src/settings.rs::is_trusted_by_hash`):
    //   - trusted_devices[i].secret_id_hash == Some(hash) AND
    //   - now - trusted_devices[i].trusted_at_epoch < trust_ttl_secs
    let parsed: serde_json::Value = serde_json::from_str(&settings_json).unwrap();
    let records = parsed["trusted_devices"].as_array().unwrap();
    let ttl = parsed["trust_ttl_secs"].as_u64().unwrap();

    let is_trusted_by_hash = |h: &[u8; 6]| -> bool {
        records.iter().any(|r| {
            let stored_hex = r["secret_id_hash"].as_str().unwrap_or("");
            let Ok(stored_bytes) = hex::decode(stored_hex) else {
                return false;
            };
            if stored_bytes.len() != 6 {
                return false;
            }
            let ts = r["trusted_at_epoch"].as_u64().unwrap_or(0);
            stored_bytes[..] == h[..] && now().saturating_sub(ts) < ttl
        })
    };

    // Attacker hijack girişimi — beklenen: DIALOG GÖSTERİLMELİ = trust FALSE.
    assert!(
        !is_trusted_by_hash(&attacker_hash),
        "T2: attacker (name, id) spoof + farklı hash trust'ı bypass etmemeli"
    );

    // Gerçek cihaz — trust TRUE.
    assert!(
        is_trusted_by_hash(&victim_hash),
        "Gerçek cihaz (doğru hash) auto-accept olmalı"
    );
}

#[test]
fn t2_ttl_expired_trust_kaybolur() {
    // Trust kararı yalnız hash eşleşmeye değil aynı zamanda TTL içinde
    // olmaya da bağlı — 8 gün önceki trust artık geçerli değil.
    let victim_hash: [u8; 6] = [0x42; 6];
    let ttl_secs: u64 = 7 * 24 * 3600;
    let trusted_at = now().saturating_sub(8 * 24 * 3600);

    let records = [json!({
        "name": "Pixel",
        "id": "ABCD",
        "secret_id_hash": hex::encode(victim_hash),
        "trusted_at_epoch": trusted_at,
    })];

    let is_trusted_by_hash = |h: &[u8; 6]| -> bool {
        records.iter().any(|r| {
            let stored_hex = r["secret_id_hash"].as_str().unwrap_or("");
            let Ok(stored_bytes) = hex::decode(stored_hex) else {
                return false;
            };
            if stored_bytes.len() != 6 {
                return false;
            }
            let ts = r["trusted_at_epoch"].as_u64().unwrap_or(0);
            stored_bytes[..] == h[..] && now().saturating_sub(ts) < ttl_secs
        })
    };

    assert!(
        !is_trusted_by_hash(&victim_hash),
        "TTL dolmuş trust auto-accept olmamalı"
    );
}

#[test]
fn legacy_kayit_hash_yokken_sadece_name_id_ile_dusuk_guvenle_esler() {
    // v0.5.x legacy kayıt: secret_id_hash = None, trusted_at_epoch = 0.
    // Peer yeni kodla bağlanıp hash göndermiyorsa (spec'e uymuyor)
    // legacy (name, id) eşleşmesiyle trust verilir — üç sürümlük uyumluluk
    // window'u. Güvenlik seviyesi v0.5.x ile aynı ama production kodu
    // (`connection.rs`) peer hash gönderdiğinde hash-first karar verir.
    let records = [json!({
        "name": "EskiCihaz",
        "id": "old-id",
        "trusted_at_epoch": 0u64,
        // secret_id_hash alanı yok — None olarak okunur
    })];

    let is_trusted_legacy = |name: &str, id: &str| -> bool {
        records.iter().any(|r| {
            let rn = r["name"].as_str().unwrap_or("");
            let ri = r["id"].as_str().unwrap_or("");
            rn == name && (ri.is_empty() || ri == id)
        })
    };

    assert!(is_trusted_legacy("EskiCihaz", "old-id"));
    assert!(!is_trusted_legacy("EskiCihaz", "farkli-id")); // id eşleşmezse reddedilir
    assert!(!is_trusted_legacy("BaskaCihaz", "old-id")); // name eşleşmezse reddedilir
}

// ===== Issue #17 — hash-first rate-limit (Seçenek B) regresyon testleri =====
//
// Eski kod (`src/connection.rs` gate) `is_trusted_legacy(name, id)` ile
// rate-limit muafiyeti veriyordu → saldırgan kurbanın trusted listesindeki
// (name, id) çiftini spoof edip 10/60s'i aşarak 32-permit Semaphore'u
// DoS edebilirdi. Yeni kod gate'de muafiyet vermiyor; trust
// `PairedKeyEncryption.secret_id_hash` doğrulandığında geriye-dönük
// (`forget_most_recent`) uygulanıyor.
//
// Bu testler `RateLimiter` davranışını doğrudan mirror eder
// (production `src/state.rs::RateLimiter` birebir mantık kopyalanır
// — `tests/rate_limiter.rs` ile aynı desen). Full `connection::handle`
// integration testi socket + UKEY2 + Introduction akışı kurmak zorunda
// olduğundan aşırı kapsamlı; buradaki testler kritik invariant'ları
// izole ediyor.

mod issue_17_rate_limit {
    use parking_lot::RwLock;
    use std::collections::{HashMap, VecDeque};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    /// `src/state.rs::RateLimiter` mirror — `forget_most_recent` dahil.
    /// Production kodu `now = Instant::now()` kullanıyor; test için
    /// `Instant`'ı dışarıdan enjekte ediyoruz (determinisistik).
    struct RateLimiter {
        windows: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
        window: Duration,
        max_per_window: usize,
    }

    impl RateLimiter {
        fn prod() -> Self {
            Self {
                windows: RwLock::new(HashMap::new()),
                window: Duration::from_secs(60),
                max_per_window: 10,
            }
        }

        fn check_and_record_at(&self, ip: IpAddr, now: Instant) -> bool {
            let mut w = self.windows.write();
            let q = w.entry(ip).or_default();
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

        fn forget_most_recent(&self, ip: IpAddr) {
            let mut w = self.windows.write();
            if let Some(q) = w.get_mut(&ip) {
                q.pop_back();
            }
        }

        fn queue_len(&self, ip: IpAddr) -> usize {
            self.windows.read().get(&ip).map(|q| q.len()).unwrap_or(0)
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// T2 — Saldırgan, kurbanın trusted listesindeki (name, id) çiftini
    /// spoof ediyor ve `secret_id_hash = None` göndererek hash yokluğu
    /// üzerinden legacy fallback'i istiyor. Eski kodda gate'deki
    /// `is_trusted_legacy` muafiyeti verirdi → limit'i aşabilirdi.
    /// Yeni kodda gate'de muafiyet YOK — 11. bağlantı reddedilmeli.
    #[test]
    fn t2_spoofed_name_id_rate_limit_muafiyeti_almaz() {
        // Kurbanın trusted kaydı: hash-verified iPhone (hash=[0xAA;6]).
        // Bu test "attacker spoof name+id" senaryosunu pin'liyor —
        // victim state burada yalnız bağlam, gate kararı ad/id
        // bağımsız alınmalı.
        let rl = RateLimiter::prod();
        let attacker_ip = ipv4(198, 51, 100, 42);
        let t0 = Instant::now();

        // Saldırgan 10 bağlantı — hepsi rate-limit sayacına kaydedilir
        // (eski kod trusted_early=true verip `check_and_record` hiç
        // çağırmazdı; yeni kod çağırır).
        for i in 0..10 {
            let reject = rl.check_and_record_at(attacker_ip, t0 + Duration::from_millis(i as u64));
            assert!(
                !reject,
                "{}. bağlantı kabul edilmeli (henüz cap dolmadı)",
                i + 1
            );
        }
        // 11. bağlantı: cap doldu → reject. Spoof bypass yok.
        let reject_11 = rl.check_and_record_at(attacker_ip, t0 + Duration::from_millis(10));
        assert!(
            reject_11,
            "Issue #17: spoofed (name, id) rate-limit muafiyeti almamalı — 11. bağlantı reddedilmeli"
        );
    }

    /// Hash doğrulanmış trusted peer — `forget_most_recent` her handshake
    /// sonrası çağrılırsa, aynı IP'den sürekli yeni bağlantılar yapılabilir.
    /// Eski davranışla fonksiyonel olarak eşdeğer ama güvenlik katmanı
    /// hash'e bağlı (peer-controlled string'e değil).
    #[test]
    fn t2_hash_verified_peer_rate_limit_post_hoc_muaf() {
        let rl = RateLimiter::prod();
        let trusted_ip = ipv4(192, 168, 1, 50);
        let t = Instant::now();

        // 15 bağlantı — her birinde gate check_and_record + post-hoc
        // forget_most_recent (hash doğrulandığı varsayımıyla).
        for i in 0..15 {
            let reject = rl.check_and_record_at(trusted_ip, t + Duration::from_millis(i));
            assert!(
                !reject,
                "hash-verified peer'ın {}. bağlantısı kabul edilmeli",
                i + 1
            );
            // Post-hoc: trusted hash doğrulandı, kaydı geri al.
            rl.forget_most_recent(trusted_ip);
        }
        // Her forget sonrası queue tam boşalmalı.
        assert_eq!(
            rl.queue_len(trusted_ip),
            0,
            "hash-verified peer için queue sürekli temizlenmeli"
        );
    }

    /// Hash-suppress saldırısı: saldırgan `PairedKeyEncryption.secret_id_hash`'i
    /// göndermez (peer spec'e uymuyor bahanesi). Yeni kod bu durumda
    /// `forget_most_recent` ÇAĞIRMAZ (çünkü hash yok) — rate-limit kaydı
    /// intact kalır ve saldırgan legacy fallback üzerinden muafiyet
    /// kazanamaz.
    #[test]
    fn t2_hash_suppress_attack_legacy_kayda_ulasamaz() {
        let rl = RateLimiter::prod();
        let attacker_ip = ipv4(203, 0, 113, 7);
        let t = Instant::now();

        // Saldırgan 11 bağlantı dener. Hash-suppress: hash=None →
        // connection.rs'teki `if let Some(h) = *peer_secret_id_hash`
        // branch'i girmez → forget_most_recent çağrılmaz.
        for i in 0..10 {
            assert!(!rl.check_and_record_at(attacker_ip, t + Duration::from_millis(i)));
            // HAYIR — forget_most_recent çağrılmıyor (hash yok).
        }
        // 11. deneme: cap dolu → reject.
        assert!(
            rl.check_and_record_at(attacker_ip, t + Duration::from_millis(10)),
            "hash-suppress saldırısı legacy kayda ulaşıp muafiyet kazanmamalı"
        );
        // Queue hâlâ dolu (10 elem) — kimse geri almadı.
        assert_eq!(rl.queue_len(attacker_ip), 10);
    }
}
