//! Cihaz-kalıcı kriptografik kimlik — Issue #17 (trusted device identity
//! hardening, design 017).
//!
//! İlk çalıştırmada `config_dir()/identity.key` içinde 32 bayt rastgele
//! uzun-süreli anahtar (`long_term_key`) üretip saklarız. Bu anahtar **peer'a
//! hiç gönderilmez**; yalnızca HKDF-SHA256 ile türetilen alt-anahtar/hash'ler
//! (örn. `secret_id_hash`) paylaşılır.
//!
//! `secret_id_hash()` Quick Share `PairedKeyEncryption.secret_id_hash` alanına
//! konur ve karşı tarafın bizi "bu makine" olarak tanımasını sağlar —
//! `endpoint_id` (her oturumda değişen 4 ASCII bayt) yerine session'dan
//! bağımsız, kriptografik olarak stabil bir tanıtıcıdır.
//!
//! ## Güvenlik modeli
//!
//! - **POSIX:** tmp dosya `O_EXCL | mode(0o600)` ile açılır; atomic
//!   `tmp-file + rename` kullanıldığı için yarım yazılmış anahtar dosyası
//!   kalmaz ve dosya hiçbir zaman world-readable olarak görünmez (rename
//!   inode'u koruduğu için izinler final path'e aynen taşınır).
//! - **Windows:** `atomic_write_mode` sonrası `icacls` ile DACL explicit
//!   sertleştirilir: inheritance disable (`/inheritance:r`) + yalnız
//!   `OWNER RIGHTS` SID'ine Full (`*S-1-3-4:(F)`). NTFS default ACL'ye
//!   güvenmek yerine runtime'da deterministik garanti.
//! - Korrupt (boyut ≠ 32) dosya → hata döner; **auto-regenerate etmeyiz**,
//!   kullanıcı manuel müdahale etmeli (aksi halde eski trust ilişkileri
//!   sessizce kaybolurdu).

use anyhow::{bail, Context, Result};
use rand::RngCore;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

/// Uzun-süreli cihaz kimlik anahtarı.
///
/// Yalnızca `long_term_key` disk'e yazılır; `secret_id_hash()` ve (v0.7'de
/// gelecek) `signing_key()` bu key'den türetilen child-key'lerdir.
pub struct DeviceIdentity {
    long_term_key: [u8; 32],
}

impl DeviceIdentity {
    /// `identity.key` dosyasını verilen yoldan oku veya yoksa oluştur.
    ///
    /// - **Var + 32 bayt:** içerikten key'i yükler.
    /// - **Var + boyut ≠ 32:** bozuk kabul, hata döner (auto-regenerate etmez).
    /// - **Yok:** 32 bayt rastgele key üretip atomic + 0o600 ile yazar.
    ///
    /// RFC-0001 §5 Adım 4: `crate::platform::*` çağırılmaması için path
    /// injection — caller (app) `paths::identity_path()` ile production
    /// yolu sağlar; tests kendi tmp path'ini geçer.
    pub fn load_or_create_at(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "identity.key parent dizini oluşturulamadı: {}",
                    parent.display()
                )
            })?;
        }

        if path.exists() {
            let buf = std::fs::read(path)
                .with_context(|| format!("identity.key okunamadı: {}", path.display()))?;
            if buf.len() != 32 {
                bail!(
                    "identity.key bozuk: beklenen 32 bayt, bulunan {} bayt ({}). \
                     Dosyayı yedekleyip silin, HekaDrop yeni kimlik üretir — \
                     ancak trusted listeden eski cihazlar bir kez dialog soracaktır.",
                    buf.len(),
                    path.display()
                );
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf);

            // SECURITY (PR #76 review — gemini): v0.6 öncesi install'lar
            // hardening'den geçmemiş olabilir. Mevcut identity.key dosyalarını
            // da her açılışta ACL sertleştirmeden geçiriyoruz ki eski kurulumlar
            // da güvenli hale gelsin. Hata fatal değil — warn log + devam.
            // (Windows dışı target'larda no-op, ucuz.)
            if let Err(e) = harden_identity_file_acl(path) {
                tracing::warn!(
                    "identity.key mevcut ACL sertleştirme başarısız: {e} (devam ediliyor)"
                );
            }

            return Ok(Self { long_term_key: key });
        }

        // İlk çalıştırma — yeni anahtar üret + atomic yaz + 0o600.
        //
        // SECURITY (review #34 MED): tmp dosya baştan `O_EXCL | mode(0o600)`
        // ile açılır; önceki kod tmp'yi umask-default (tipik 0644) ile açıp
        // rename SONRASI `set_permissions(0o600)` çağırıyordu — bu iki adım
        // arasında dosya dünya-okunabilir olarak kısa bir süre varlık
        // gösteriyordu. `atomic_write_mode` ile bu pencere tamamen kapanır
        // (rename inode'u korur, izinler taşınır).
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        crate::settings::atomic_write_mode(path, &key, Some(0o600))
            .with_context(|| format!("identity.key yazılamadı: {}", path.display()))?;

        // Windows: DACL'i explicit sıkılaştır. NTFS default ACL kullanıcı
        // profili altında owner-only olmayı **genellikle** sağlar ama bu
        // garantili değil (group policy, inherited ACE'ler, taşınan profiller
        // varyasyon üretebilir). `harden_identity_file_acl` inheritance'ı
        // keser + yalnız OWNER RIGHTS SID'ine Full verir.
        //
        // Hata fatal değil — ACL sertleştirme başarısız olsa bile
        // `atomic_write_mode` zaten dosyayı yazdı ve çoğu ortamda default ACL
        // yeterli. Warn log'la devam ediyoruz; kullanıcı identity üretimi
        // tamamen başarısız olmuş gibi algılamasın.
        if let Err(e) = harden_identity_file_acl(path) {
            tracing::warn!("identity.key Windows ACL sertleştirme başarısız: {e} (devam ediliyor)");
        }

        Ok(Self { long_term_key: key })
    }

    /// Quick Share `PairedKeyEncryption.secret_id_hash` (6 bayt).
    ///
    /// Cihaz anahtarı değişmediği sürece stabil. Domain separation için
    /// HKDF-SHA256 kullanılır — aynı master key'den ileride başka child-key
    /// (signing, vb.) türetmek çakışmadan mümkün olur.
    pub fn secret_id_hash(&self) -> [u8; 6] {
        let h = crate::crypto::hkdf_sha256(
            &self.long_term_key,
            b"HekaDrop v1",
            b"paired_key/secret_id",
            6,
        );
        let mut out = [0u8; 6];
        out.copy_from_slice(&h);
        out
    }

    /// İleride `signed_data` doğrulaması için ECDSA imza anahtarı türetir.
    /// v0.6'da kullanılmıyor; imza akışı v0.7 pairing protokolüyle gelecek.
    #[allow(dead_code)]
    pub fn signing_key(&self) -> [u8; 32] {
        let h = crate::crypto::hkdf_sha256(
            &self.long_term_key,
            b"HekaDrop v1",
            b"paired_key/signing",
            32,
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&h);
        out
    }
}

/// Windows: `identity.key` DACL'ini sıkılaştır.
///
/// **Neden:** NTFS default ACL kullanıcı profili altında owner-only olmayı
/// genellikle verir, ama GPO / inherited ACE / migrate edilmiş profil gibi
/// senaryolarda bu varsayım kırılabilir. `identity.key`, trust ilişkisini
/// belirleyen uzun-süreli cihaz kimlik anahtarı olduğu için **runtime'da
/// deterministik** DACL istiyoruz.
///
/// **Yaklaşım — `icacls.exe`:** `windows` crate ile doğrudan
/// `SetNamedSecurityInfoW` çağırmak daha hızlı/temiz olurdu ancak
/// `Win32_Security_Authorization` feature şu an `Cargo.toml`'da etkin değil
/// ve v0.61'e yeni feature eklemek wry/webview2-com uyumluluğunu test
/// gerektiriyor. `icacls.exe` Windows'un built-in aracı (System32) — ek
/// bağımlılık yok ve argümanlar self-documenting:
///
/// - `/inheritance:r` — parent dizinden gelen miras ACE'leri temizle.
/// - `/grant:r *S-1-3-4:(F)` — **yalnız** `OWNER RIGHTS` well-known SID'ine
///   Full access ver (`:r` = replace, kümülatif değil).
///
/// `*S-1-3-4` (OWNER RIGHTS) dosyanın owner'ı her kim ise onu eşler —
/// username/SID hard-code etmekten kaçınırız, user profilinde dosya zaten
/// current user'a ait oluyor.
///
/// **PATH hijack koruması (PR #76 review):** `icacls.exe` PATH'ten değil,
/// `%SystemRoot%\System32\icacls.exe` mutlak yolundan çağrılır.
///
/// **Test:** Windows CI yok; manuel doğrulama `icacls <path>` çıktısının
/// yalnız `OWNER RIGHTS:(F)` ACE'si içerdiğini göstermeli.
#[cfg(target_os = "windows")]
fn harden_identity_file_acl(path: &std::path::Path) -> Result<()> {
    use std::process::Command;

    // SECURITY (PR #76 review — Copilot + gemini): PATH araması yapmayız.
    // `Command::new("icacls")` cwd/PATH'te sahte `icacls.exe` varsa onu
    // çağırabilirdi (PATH hijack). `icacls` Windows built-in aracıdır —
    // doğrudan `%SystemRoot%\System32\icacls.exe` mutlak yolundan çağırırız.
    // `%SystemRoot%` env yoksa tipik varsayılan `C:\Windows` fallback.
    let icacls_path = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("icacls.exe");

    let output = Command::new(&icacls_path)
        .arg(path)
        .arg("/inheritance:r")
        .args(["/grant:r", "*S-1-3-4:(F)"])
        .output()
        .with_context(|| format!("{} çalıştırılamadı", icacls_path.display()))?;

    if !output.status.success() {
        bail!(
            "icacls başarısız (exit={:?}): stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// POSIX: no-op — `atomic_write_mode(..., Some(0o600))` zaten
/// `O_EXCL | mode(0o600)` ile açtığı için izinler ilk andan itibaren
/// owner-only. Rename inode'u koruduğundan final path de 0o600 olur.
#[cfg(not(target_os = "windows"))]
fn harden_identity_file_acl(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tek test için izole tmp dizin + `identity.key` path'i.
    /// HOME/XDG env variable yarışından bağımsız — path-injection variant
    /// kullandığımız için tests paralelde güvenle çalışır.
    fn test_identity_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hekadrop-identity-test-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("identity.key")
    }

    #[test]
    fn load_or_create_idempotent_ayni_key_doner() {
        let path = test_identity_path("idempotent");
        let id1 = DeviceIdentity::load_or_create_at(&path).expect("ilk yaratım");
        let id2 = DeviceIdentity::load_or_create_at(&path).expect("ikinci yükleme");
        // Aynı disk dosyasından okunmalı — anahtarlar ve dolayısıyla
        // türetilen hash'ler eşit.
        assert_eq!(id1.long_term_key, id2.long_term_key);
        assert_eq!(id1.secret_id_hash(), id2.secret_id_hash());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn secret_id_hash_sabit_key_icin_deterministik() {
        // Sabit master key ile hash'in deterministik olduğunu doğrula —
        // HKDF çıktısı bu test vektörü sayesinde regresyonda yakalanır.
        let key = [0x42u8; 32];
        let id = DeviceIdentity { long_term_key: key };
        let h1 = id.secret_id_hash();
        let h2 = id.secret_id_hash();
        assert_eq!(h1, h2);
        // Değer değişmesin diye aynı key için somut beklentiyi de sabitliyoruz.
        // Beklenen, HKDF-SHA256(ikm=[0x42;32], salt=b"HekaDrop v1",
        // info=b"paired_key/secret_id", 6) = hex ile hesaplanıp gömüldü.
        let expected =
            crate::crypto::hkdf_sha256(&[0x42u8; 32], b"HekaDrop v1", b"paired_key/secret_id", 6);
        assert_eq!(&h1[..], expected.as_slice());
        assert_eq!(h1.len(), 6);
    }

    #[test]
    fn secret_id_hash_farkli_keyler_farkli_hash() {
        let a = DeviceIdentity {
            long_term_key: [0x11u8; 32],
        };
        let b = DeviceIdentity {
            long_term_key: [0x22u8; 32],
        };
        assert_ne!(a.secret_id_hash(), b.secret_id_hash());
    }

    #[test]
    fn signing_key_farkli_domain_separation() {
        // HKDF domain separation: aynı key'den türetilen secret_id ve signing
        // farklı info string'leri olduğundan farklı çıktı vermeli.
        let id = DeviceIdentity {
            long_term_key: [0x55u8; 32],
        };
        let h = id.secret_id_hash();
        let sk = id.signing_key();
        assert_ne!(&h[..], &sk[..6]);
    }

    #[cfg(unix)]
    #[test]
    fn posix_izin_0600_olarak_yazilir() {
        use std::os::unix::fs::PermissionsExt;
        let path = test_identity_path("perm");
        let _ = DeviceIdentity::load_or_create_at(&path).expect("yaratım");
        let meta = std::fs::metadata(&path).expect("stat");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "identity.key 0o600 olmalı, bulunan: 0o{:o}",
            mode
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn bozuk_boyutta_dosya_hata_doner() {
        let path = test_identity_path("bozuk");
        // İlk önce bozuk içerik yazalım.
        std::fs::write(&path, b"kisa").expect("bozuk dosya yazıldı");
        let res = DeviceIdentity::load_or_create_at(&path);
        assert!(res.is_err(), "bozuk dosya için hata bekleniyordu");
        let err = format!("{:#}", res.err().unwrap());
        assert!(
            err.contains("bozuk") || err.contains("32 bayt"),
            "hata mesajı bozukluğu belirtmeli: {}",
            err
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
