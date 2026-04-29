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

//! Legacy TTL soft-sunset — Issue #17 (Seçenek D).
//!
//! v0.6 `prune_expired` eskiden legacy kayıtlara (`secret_id_hash == None`)
//! hiç dokunmazdı — sınırsız yaşarlardı. Bu, hash-suppress saldırısıyla
//! birleştiğinde saldırgana "kurban 90 gün önce trust ettiği ama artık
//! hash-upgrade olmamış legacy kaydı yoluyla muafiyet kazanma" şansı
//! tanırdı. Issue #17 kapsamında legacy kayıtlara soft-sunset uygulandı:
//!
//! * `trusted_at_epoch == 0` → v0.5→v0.6 upgrade kayıtları (epoch
//!   bilinmiyordu) **sınırsız korunur** (opportunistic hash-upgrade
//!   şansı için).
//! * `trusted_at_epoch > 0` → 90 gün içinde hash-upgrade olmazsa silinir.
//!
//! Hash'li kayıtlar `Settings.trust_ttl_secs` (default 7 gün) ile
//! devam eder; bu test dosyası legacy'ye özgü yeni semantiği pin'ler.

use hekadrop::settings::{Settings, TrustedDevice};

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Legacy kayıt (`hash = None`) 90 günden eski ise `prune_expired` silmeli.
/// Saldırı yüzeyini sınırlar: "yıllar önce trust edilmiş ama hash-upgrade
/// olmamış" peer'lar sonsuza kadar legacy fallback sunmaz.
#[test]
fn legacy_kayit_90_gun_sonra_expired() {
    let mut s = Settings::default();
    // 91 gün önce trust edilmiş legacy kayıt.
    let very_old = now_epoch().saturating_sub(91 * 24 * 3600);
    s.trusted_devices.push(TrustedDevice {
        name: "EskiCihaz".into(),
        id: "legacy-id".into(),
        secret_id_hash: None,
        trusted_at_epoch: very_old,
    });
    // Taze legacy kayıt (5 gün önce) — kalmalı.
    let fresh = now_epoch().saturating_sub(5 * 24 * 3600);
    s.trusted_devices.push(TrustedDevice {
        name: "TazeLegacy".into(),
        id: "legacy-id-2".into(),
        secret_id_hash: None,
        trusted_at_epoch: fresh,
    });

    let removed = s.prune_expired();
    assert_eq!(
        removed, 1,
        "90 gün öncesi legacy kayıt silinmeli; taze legacy kalmalı"
    );
    assert!(
        !s.trusted_devices.iter().any(|d| d.name == "EskiCihaz"),
        "91 gün öncesi legacy kayıt listede olmamalı"
    );
    assert!(
        s.trusted_devices.iter().any(|d| d.name == "TazeLegacy"),
        "5 gün öncesi legacy kayıt (90 gün altında) korunmalı"
    );
}

/// v0.5 → v0.6 upgrade kayıtları `trusted_at_epoch == 0` ile yazıldı
/// (epoch bilinmiyordu). Bu kayıtlar **sınırsız** korunur — kullanıcının
/// eski trust kararını upgrade sırasında kaybetmemesi için.
/// Opportunistic hash-upgrade: peer sonraki bağlantısında
/// `add_trusted_with_hash` ile kayıt yenilenir ve epoch set edilir.
#[test]
fn legacy_kayit_epoch_0_korunur() {
    let mut s = Settings::default();
    s.trusted_devices.push(TrustedDevice {
        name: "v05Upgrade".into(),
        id: "old-id".into(),
        secret_id_hash: None,
        trusted_at_epoch: 0, // v0.5 upgrade işareti
    });
    // Karışık: aynı anda hash'li expired kayıt — silinmeli, legacy kalmalı.
    s.trusted_devices.push(TrustedDevice {
        name: "EskiHash".into(),
        id: "hash-id".into(),
        secret_id_hash: Some([0x42u8; 6]),
        trusted_at_epoch: now_epoch().saturating_sub(s.trust_ttl_secs + 100),
    });

    let removed = s.prune_expired();
    assert_eq!(removed, 1, "expired hash kayıt silinmeli");
    assert!(
        s.trusted_devices.iter().any(|d| d.name == "v05Upgrade"),
        "epoch=0 v0.5 upgrade kayıt sınırsız korunmalı (opportunistic upgrade)"
    );
    assert!(
        !s.trusted_devices.iter().any(|d| d.name == "EskiHash"),
        "expired hash kayıt temizlenmeli"
    );
}
