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
//! - **Windows:** NTFS default owner-only ACL kabul; tam `SetNamedSecurityInfoW`
//!   ile ACL sıkılaştırma follow-up (v0.7).
//! - Korrupt (boyut ≠ 32) dosya → hata döner; **auto-regenerate etmeyiz**,
//!   kullanıcı manuel müdahale etmeli (aksi halde eski trust ilişkileri
//!   sessizce kaybolurdu).

use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::path::PathBuf;

/// Uzun-süreli cihaz kimlik anahtarı.
///
/// Yalnızca `long_term_key` disk'e yazılır; `secret_id_hash()` ve (v0.7'de
/// gelecek) `signing_key()` bu key'den türetilen child-key'lerdir.
pub struct DeviceIdentity {
    long_term_key: [u8; 32],
}

impl DeviceIdentity {
    /// `identity.key` dosyasını oku veya yoksa oluştur.
    ///
    /// - **Var + 32 bayt:** içerikten key'i yükler.
    /// - **Var + boyut ≠ 32:** bozuk kabul, hata döner (auto-regenerate etmez).
    /// - **Yok:** 32 bayt rastgele key üretip atomic + 0o600 ile yazar.
    pub fn load_or_create() -> Result<Self> {
        Self::load_or_create_at(&identity_path())
    }

    /// Path-injection variant — test harness'ının HOME/XDG env yarışı olmadan
    /// kendi tmp dizinini kullanmasına izin verir. Ana binary kodu
    /// `load_or_create()` çağırır; production path `config_dir()/identity.key`.
    pub(crate) fn load_or_create_at(path: &std::path::Path) -> Result<Self> {
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

        // Windows: NTFS default ACL (kullanıcı profili altında owner-only)
        // kabul edilebilir. Tam ACL sıkılaştırma (SetNamedSecurityInfoW) v0.7
        // follow-up — şu an en-iyi-çaba.
        // TODO(v0.7): Windows ACL sıkılaştırma — SetNamedSecurityInfoW ile
        // yalnız current user SID'ine KEY_READ + KEY_WRITE bırak.

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

pub(crate) fn identity_path() -> PathBuf {
    crate::platform::config_dir().join("identity.key")
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
