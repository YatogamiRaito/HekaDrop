//! Kalıcı ayarlar — platforma göre:
//!   - macOS: `~/Library/Application Support/HekaDrop/config.json`
//!   - Linux: `~/.config/HekaDrop/config.json`
//!
//! JSON formatı insan tarafından okunabilir, ileri uyumlu. Bilinmeyen alanlar yok
//! sayılır (`#[serde(default)]`).
//!
//! ## Güven kaydı (Bug #32)
//! Güvenilen cihazlar yalnız isimle değil, **isim + kalıcı kimlik** çifti ile
//! tanınır. Aksi halde iki farklı telefon aynı "Samsung A52" adını kullanırsa
//! her ikisi de otomatik kabul edilirdi — spoofing yüzeyi. Kimlik olarak
//! peer'ın `endpoint_id` veya pubkey hash'i kullanılır (`&str`, connection.rs
//! tarafından verilir).
//!
//! JSON migrasyonu ("backward compat"): Eski formatlar diskte `Vec<String>`
//! olarak yer aldığında her string `TrustedDevice { name: s, id: "" }` olarak
//! yüklenir. Boş id, yalnızca isim eşleşmesi kabul edecek yasal legacy değer
//! demektir. Kullanıcı "Kabul + güven" seçtiğinde yeni kayıt gerçek id ile
//! yazılır ve legacy-empty-id kaydın üzerine geçer (id-specific first-match).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Kullanıcının "Kabul + güven" ile onayladığı bir cihaz kaydı.
///
/// `name` insan-okunur görünen ad (ör. "Pixel 8"), `id` ise cihazın
/// kalıcı kimliği (`endpoint_id`, pubkey hash vb.). İsim çakışmalarını
/// önlemek için `is_trusted` her ikisini de kontrol eder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDevice {
    pub name: String,
    /// Peer'ın kalıcı tanıtıcısı. Eski (legacy) kayıtlar için boş olabilir;
    /// bu durumda yalnızca ad eşleşmesi ile trusted kabul edilir — bu,
    /// migrasyon sırasında kullanıcının eski güven kararlarını kaybetmesini
    /// önleyen bir compromise'dır.
    pub id: String,
}

impl TrustedDevice {
    /// UI'da "Samsung A52 (a1b2c3d4)" şeklinde göstermek için kısa format.
    /// ID boşsa (legacy kayıt) sadece ad döner.
    pub fn display(&self) -> String {
        if self.id.is_empty() {
            self.name.clone()
        } else {
            let short: String = self.id.chars().take(8).collect();
            format!("{} ({})", self.name, short)
        }
    }
}

/// Uygulama ayarları. `#[serde(default)]` ile ileri uyumlu — bilinmeyen alanlar
/// okunurken atlanır; eksik alanlar default değerlerle doldurulur.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    /// Kullanıcı tarafından atanan görünen ad (boş bırakılırsa `scutil --get ComputerName`).
    #[serde(default)]
    pub device_name: Option<String>,

    /// İndirme dizini (boş bırakılırsa `~/Downloads`).
    #[serde(default)]
    pub download_dir: Option<PathBuf>,

    /// True ise Introduction alındığında kullanıcı onayı istenmeden otomatik kabul edilir.
    /// Güvenliği zayıflatır; varsayılan false.
    #[serde(default)]
    pub auto_accept: bool,

    /// Kullanıcının "Kabul + güven" ile onayladığı cihazlar.
    ///
    /// Bu listedeki kayıtlardan (ad + id çifti) gelen aktarımlar dialog
    /// göstermeden kabul edilir ve rate limiting uygulanmaz (memory kuralı:
    /// trusted cihazlar rate limit dışıdır).
    ///
    /// JSON'da hem yeni biçim (`[{"name": "...", "id": "..."}]`) hem de eski
    /// biçim (`["ad1", "ad2"]`) kabul edilir — bkz. [`migrate_trusted_value`].
    #[serde(default, deserialize_with = "deserialize_trusted_devices")]
    pub trusted_devices: Vec<TrustedDevice>,
}

impl Settings {
    /// Verilen `(name, id)` çifti trusted listede varsa `true`.
    ///
    /// Eşleşme kuralı:
    ///   * Kaydın `id` alanı doluysa **hem ad hem id** eşleşmeli (güvenli yol).
    ///   * Kaydın `id` alanı boşsa (legacy kayıt) **yalnız ad** eşleşmesi yeter
    ///     — bu, config migrasyonu sırasında eski güven kararlarını kaybetmemek
    ///     için bilinçli bir taviz. Kullanıcı aynı cihazı tekrar "Kabul + güven"
    ///     seçerse [`add_trusted`] kaydı gerçek id'yle günceller.
    pub fn is_trusted(&self, device_name: &str, id: &str) -> bool {
        if device_name.is_empty() {
            return false;
        }
        self.trusted_devices
            .iter()
            .any(|d| d.name == device_name && (d.id.is_empty() || d.id == id))
    }

    /// Yeni bir güven kaydı ekler.
    ///
    /// İdempotent: tamamen aynı `(name, id)` çifti zaten varsa no-op.
    /// Özel durum: aynı ad için legacy (id=boş) bir kayıt varsa ve şimdi
    /// gerçek bir id geliyorsa, legacy kayıt upgrade edilir (ad+id yazılır).
    /// Boş ad reddedilir (anlamsız).
    pub fn add_trusted(&mut self, device_name: &str, id: &str) {
        if device_name.is_empty() {
            return;
        }
        // Birebir aynı kayıt var mı?
        if self
            .trusted_devices
            .iter()
            .any(|d| d.name == device_name && d.id == id)
        {
            return;
        }
        // Legacy upgrade: aynı ad, boş id → id ile güncelle.
        if !id.is_empty() {
            if let Some(existing) = self
                .trusted_devices
                .iter_mut()
                .find(|d| d.name == device_name && d.id.is_empty())
            {
                existing.id = id.to_string();
                return;
            }
        }
        self.trusted_devices.push(TrustedDevice {
            name: device_name.to_string(),
            id: id.to_string(),
        });
    }

    /// Yalnızca isme göre tüm eşleşen kayıtları siler.
    ///
    /// UI katmanı (main.rs) "trust_remove::NAME" IPC mesajıyla sadece adı
    /// iletir; geriye dönük uyum için bu imza korunur. Aynı adın birden çok
    /// id ile kaydı varsa hepsi silinir. ID tabanlı hassas silme için
    /// [`remove_trusted_by_id`] kullanın.
    pub fn remove_trusted(&mut self, device_name: &str) {
        self.trusted_devices.retain(|d| d.name != device_name);
    }

    /// `(name, id)` çiftine birebir eşleşen kaydı siler.
    ///
    /// Gelecekte UI "bu ad/id çifti güvenlikten çıksın" seçeneği sunduğunda
    /// kullanılacak — şu an yalnız testlerden çağrılıyor.
    #[allow(dead_code)]
    pub fn remove_trusted_by_id(&mut self, device_name: &str, id: &str) {
        self.trusted_devices
            .retain(|d| !(d.name == device_name && d.id == id));
    }

    /// UI için her kaydın "Ad (id_kisa)" formatında görünüm listesini döner.
    pub fn trusted_display_list(&self) -> Vec<String> {
        self.trusted_devices.iter().map(|d| d.display()).collect()
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = config_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self).context("JSON serialize")?;
        std::fs::write(&path, json).context("config.json yazılamadı")?;
        Ok(())
    }

    pub fn resolved_device_name(&self) -> String {
        self.device_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(crate::config::device_name)
    }

    pub fn resolved_download_dir(&self) -> PathBuf {
        self.download_dir
            .clone()
            .unwrap_or_else(crate::platform::default_download_dir)
    }
}

pub fn config_path() -> PathBuf {
    crate::platform::config_dir().join("config.json")
}

/// `trusted_devices` alanı için özel deserializer — hem yeni (nesne dizisi)
/// hem eski (string dizisi) JSON formatını kabul eder.
fn deserialize_trusted_devices<'de, D>(deserializer: D) -> Result<Vec<TrustedDevice>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(deserializer)?;
    migrate_trusted_value(v).map_err(D::Error::custom)
}

/// `serde_json::Value`'den `Vec<TrustedDevice>` üretir; eski string-dizisi
/// formatını `{name, id=""}` olarak çevirir.
///
/// Test edilebilirlik için pub(crate).
pub(crate) fn migrate_trusted_value(v: serde_json::Value) -> Result<Vec<TrustedDevice>, String> {
    let arr = match v {
        serde_json::Value::Null => return Ok(Vec::new()),
        serde_json::Value::Array(a) => a,
        other => {
            return Err(format!(
                "trusted_devices array bekleniyordu, geldi: {:?}",
                other
            ))
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        match item {
            serde_json::Value::String(s) => {
                // Legacy: "device-name" → {name: s, id: ""}
                if !s.is_empty() {
                    out.push(TrustedDevice {
                        name: s,
                        id: String::new(),
                    });
                }
            }
            serde_json::Value::Object(_) => {
                let td: TrustedDevice = serde_json::from_value(item)
                    .map_err(|e| format!("TrustedDevice parse: {}", e))?;
                if !td.name.is_empty() {
                    out.push(td);
                }
            }
            other => {
                return Err(format!(
                    "trusted_devices elemanı beklenmeyen tip: {:?}",
                    other
                ))
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_trusted_bos_ad_reddedilir() {
        let s = Settings::default();
        assert!(!s.is_trusted("", "some-id"));
    }

    #[test]
    fn is_trusted_yeni_kayit_ad_ve_id_eslesmeli() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");
        assert!(s.is_trusted("Pixel 7", "endpoint-abc"));
        // Farklı id → reddedilmeli (çakışma koruması).
        assert!(!s.is_trusted("Pixel 7", "endpoint-xyz"));
        // Farklı ad → reddedilmeli.
        assert!(!s.is_trusted("Galaxy", "endpoint-abc"));
    }

    #[test]
    fn is_trusted_iki_farkli_cihaz_ayni_isim_cakismaz() {
        // Bug #32 tam senaryo.
        let mut s = Settings::default();
        s.add_trusted("Samsung A52", "phone-anne");
        // Evdeki "anne"nin telefonu güvenli; "komşu"nun telefonu yalnız ad uyuşuyor
        // diye otomatik güvenli OLMAMALI.
        assert!(s.is_trusted("Samsung A52", "phone-anne"));
        assert!(!s.is_trusted("Samsung A52", "phone-komsu"));
    }

    #[test]
    fn is_trusted_legacy_bos_id_sadece_ad_ile_eslesir() {
        let mut s = Settings::default();
        s.trusted_devices.push(TrustedDevice {
            name: "EskiCihaz".into(),
            id: String::new(),
        });
        // Legacy kaydın id'si boş → her id kabul edilir (backward compat taviz).
        assert!(s.is_trusted("EskiCihaz", "any-id"));
        assert!(s.is_trusted("EskiCihaz", ""));
        // Ad yine de eşleşmeli.
        assert!(!s.is_trusted("BaskaCihaz", "any-id"));
    }

    #[test]
    fn add_trusted_idempotent() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");
        s.add_trusted("Pixel 7", "endpoint-abc");
        s.add_trusted("Pixel 7", "endpoint-abc");
        assert_eq!(s.trusted_devices.len(), 1);
    }

    #[test]
    fn add_trusted_ayni_ad_farkli_id_iki_kayit_olur() {
        let mut s = Settings::default();
        s.add_trusted("Samsung A52", "phone-1");
        s.add_trusted("Samsung A52", "phone-2");
        assert_eq!(s.trusted_devices.len(), 2);
    }

    #[test]
    fn add_trusted_legacy_upgrade_yapar() {
        // Legacy kayıt (id="") vardı; kullanıcı şimdi gerçek id ile tekrar kabul etti.
        // Üzerine yazmalı, duplicate yaratmamalı.
        let mut s = Settings::default();
        s.trusted_devices.push(TrustedDevice {
            name: "Pixel 7".into(),
            id: String::new(),
        });
        s.add_trusted("Pixel 7", "endpoint-abc");
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].id, "endpoint-abc");
    }

    #[test]
    fn add_trusted_bos_adi_reddeder() {
        let mut s = Settings::default();
        s.add_trusted("", "some-id");
        assert!(s.trusted_devices.is_empty());
    }

    #[test]
    fn remove_trusted_isim_bazli_tum_kayitlari_siler() {
        // main.rs'in "trust_remove::NAME" IPC çağrısıyla uyumlu davranış:
        // adı eşleşen tüm kayıtları siler.
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-1");
        s.add_trusted("Pixel 7", "endpoint-2");
        s.add_trusted("Galaxy", "endpoint-3");
        s.remove_trusted("Pixel 7");
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].name, "Galaxy");
    }

    #[test]
    fn remove_trusted_by_id_sadece_eslesen_kaydi_siler() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-1");
        s.add_trusted("Pixel 7", "endpoint-2");
        s.remove_trusted_by_id("Pixel 7", "endpoint-1");
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].id, "endpoint-2");
    }

    #[test]
    fn display_formati_id_kisaltilmis() {
        let d = TrustedDevice {
            name: "Pixel 7".into(),
            id: "abcdef0123456789".into(),
        };
        // İlk 8 karakter alınmalı.
        assert_eq!(d.display(), "Pixel 7 (abcdef01)");
    }

    #[test]
    fn display_formati_legacy_id_yoksa_sadece_ad() {
        let d = TrustedDevice {
            name: "Pixel 7".into(),
            id: String::new(),
        };
        assert_eq!(d.display(), "Pixel 7");
    }

    #[test]
    fn migrate_eski_string_dizisi_yeni_formata_cevrilir() {
        let v: serde_json::Value = serde_json::json!(["Pixel 7", "Galaxy"]);
        let parsed = migrate_trusted_value(v).expect("ok");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "Pixel 7");
        assert_eq!(parsed[0].id, "");
        assert_eq!(parsed[1].name, "Galaxy");
    }

    #[test]
    fn migrate_yeni_nesne_dizisi_oldugu_gibi_parse_edilir() {
        let v: serde_json::Value = serde_json::json!([
            {"name": "Pixel 7", "id": "endpoint-abc"},
            {"name": "Galaxy", "id": "endpoint-xyz"},
        ]);
        let parsed = migrate_trusted_value(v).expect("ok");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "endpoint-abc");
        assert_eq!(parsed[1].id, "endpoint-xyz");
    }

    #[test]
    fn migrate_karisik_dizi_bos_elemanlari_atlar() {
        let v: serde_json::Value = serde_json::json!([
            "",
            {"name": "", "id": "x"},
            {"name": "OK", "id": "y"}
        ]);
        let parsed = migrate_trusted_value(v).expect("ok");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "OK");
    }

    #[test]
    fn migrate_null_bos_liste_dondurur() {
        let parsed = migrate_trusted_value(serde_json::Value::Null).expect("ok");
        assert!(parsed.is_empty());
    }

    #[test]
    fn migrate_bozuk_json_hata_dondurur() {
        let v: serde_json::Value = serde_json::json!(42);
        assert!(migrate_trusted_value(v).is_err());
    }

    #[test]
    fn full_config_legacy_json_deserialize() {
        // Eski diskte böyle bir config varsa:
        let legacy = r#"{
            "device_name": "MacBook",
            "auto_accept": false,
            "trusted_devices": ["Pixel 7", "Galaxy"]
        }"#;
        let s: Settings = serde_json::from_str(legacy).expect("parse");
        assert_eq!(s.trusted_devices.len(), 2);
        assert_eq!(s.trusted_devices[0].name, "Pixel 7");
        // Legacy kayıt için is_trusted ad ile çalışmalı.
        assert!(s.is_trusted("Pixel 7", "any-id"));
    }

    #[test]
    fn roundtrip_yeni_format() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");
        s.add_trusted("Galaxy", "endpoint-xyz");
        let json = serde_json::to_string(&s).expect("serialize");
        let back: Settings = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.trusted_devices, s.trusted_devices);
    }

    #[test]
    fn concurrent_is_trusted_cagrilari_panik_atmaz() {
        // Basit thread-safety akıllılık kontrolü — is_trusted saf okuma,
        // &self alıyor, iç mutasyon yok.
        use std::sync::Arc;
        use std::thread;
        let mut s = Settings::default();
        for i in 0..50 {
            s.add_trusted(&format!("dev-{}", i), &format!("id-{}", i));
        }
        let arc = Arc::new(s);
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let s = Arc::clone(&arc);
                thread::spawn(move || {
                    for i in 0..1000 {
                        let name = format!("dev-{}", (i + t) % 50);
                        let id = format!("id-{}", (i + t) % 50);
                        assert!(s.is_trusted(&name, &id));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread ok");
        }
    }

    #[test]
    fn trusted_display_list_dogru_siralı() {
        let mut s = Settings::default();
        s.add_trusted("A", "id-aaaaaaaabbb");
        s.add_trusted("B", "");
        let list = s.trusted_display_list();
        assert_eq!(list, vec!["A (id-aaaaa)".to_string(), "B".to_string()]);
    }
}
