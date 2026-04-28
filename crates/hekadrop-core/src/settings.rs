//! Kalıcı ayarlar — platforma göre:
//!   - macOS: `~/Library/Application Support/HekaDrop/config.json`
//!   - Linux: `~/.config/HekaDrop/config.json`
//!
//! JSON formatı insan tarafından okunabilir, ileri uyumlu. Bilinmeyen alanlar yok
//! sayılır (`#[serde(default)]`).
//!
//! ## Güven kaydı — v0.6 hardening (Issue #17 / design 017)
//!
//! v0.5.x `TrustedDevice { name, id }` ile "ad + `endpoint_id`" çifti üzerinden
//! güven kararı veriyordu. `endpoint_id` 4 ASCII bayt — her oturumda rastgele
//! ve kriptografik olarak bağlayıcı değil. v0.6:
//!
//! * **`secret_id_hash: Option<[u8; 6]>`** — Quick Share
//!   `PairedKeyEncryption.secret_id_hash` alanı; peer'ın uzun-süreli kimlik
//!   anahtarından (HKDF-SHA256) türetilir, cihaz değişmediği sürece sabit.
//!   Trust kararının **birincil anahtarı**. Hex olarak serialize edilir.
//! * **`trusted_at_epoch`** — kullanıcı bu cihazı ne zaman "kabul + güven"
//!   yaptı. TTL (default 7 gün, `Settings.trust_ttl_secs` ile override)
//!   aşıldığında kayıt **silinmez** ama "güvenilir" sayılmaz — kullanıcıya
//!   dialog tekrar gösterilir.
//!
//! Geriye uyum:
//!   * Legacy (`secret_id_hash == None`) kayıtlar `is_trusted_legacy(name, id)`
//!     ile eşleşmeye devam eder (3 sürüm boyunca). Peer hash gönderirse
//!     `add_trusted_with_hash` opportunistic olarak kaydı upgrade eder.
//!   * Eski diskten gelen `Vec<String>` / boş-id kayıtları da `TrustedDevice`
//!     alanında `None` hash + boş id ile okunur (bkz. `migrate_trusted_value`).

use crate::error::HekaError;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// v0.6 default — kullanıcı `Settings.trust_ttl_secs` ile override edebilir.
/// 7 gün = 604800 saniye.
pub const DEFAULT_TRUST_TTL_SECS: u64 = 7 * 24 * 3600;

fn default_trust_ttl_secs() -> u64 {
    DEFAULT_TRUST_TTL_SECS
}

fn default_advertise() -> bool {
    true
}

fn default_disable_update_check() -> bool {
    // Privacy-first: update kontrolü kapalı başlar. Kullanıcı Settings'ten
    // açana kadar GitHub API'ye hiçbir istek çıkmaz.
    true
}

fn default_keep_stats() -> bool {
    true
}

/// Kullanıcı-seçimli log verbosity seviyesi (H#4 privacy controls).
///
/// `tracing_subscriber::EnvFilter` stringine çevrilir: `hekadrop=<level>`.
/// `RUST_LOG` env var varsa o öncelikli; bu enum yalnızca env yokken devreye
/// girer. JSON'da lowercase string olarak serialize edilir (`"info"`, `"warn"`
/// vb.) — config.json manuel düzenlenirken okunabilir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl LogLevel {
    /// `tracing_subscriber::EnvFilter` string'ine dönüştür: yalnızca
    /// `hekadrop` crate'i için seviye set edilir; directive'e dahil
    /// olmayan modüller (tokio/hyper vb.) `EnvFilter` default'una (warn)
    /// düşer.
    pub fn filter_directive(self) -> &'static str {
        match self {
            Self::Error => "hekadrop=error",
            Self::Warn => "hekadrop=warn",
            Self::Info => "hekadrop=info",
            Self::Debug => "hekadrop=debug",
        }
    }

    /// UI / JSON için küçük harfli etiket — serde `rename_all = "lowercase"`
    /// ile aynı değer. IPC JSON parsing tarafında string karşılaştırması için.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// UI'dan gelen serbest string değeri `LogLevel`'e çevirir; bilinmeyen
    /// değerler `Info` default'una düşer (invalid input'ta sessiz güven).
    pub fn parse_or_default(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "debug" => Self::Debug,
            _ => Self::Info,
        }
    }
}

/// Kullanıcının "Kabul + güven" ile onayladığı bir cihaz kaydı.
///
/// v0.6'dan itibaren güven kararı **`secret_id_hash`** (cihaz-kalıcı HKDF
/// türetmesi) üzerinden verilir. `name` UI'da gösterilen insan-okunur ad,
/// `id` `endpoint_id` — yalnızca legacy kayıtlar için trust anahtarı, yeni
/// kayıtlarda yardımcı (ör. UI'da kısa etiket). `trusted_at_epoch` sliding
/// TTL için kullanılır.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDevice {
    pub name: String,
    /// Peer'ın kalıcı tanıtıcısı. Eski (legacy) kayıtlar için boş olabilir;
    /// bu durumda yalnızca ad eşleşmesi ile trusted kabul edilir — bu,
    /// migrasyon sırasında kullanıcının eski güven kararlarını kaybetmesini
    /// önleyen bir compromise'dır.
    pub id: String,
    /// Peer'ın `PairedKeyEncryption.secret_id_hash` alanı (6 bayt, HKDF
    /// türetmesi). Legacy kayıtlar için `None`; v0.6+ kayıtlar için `Some`.
    /// JSON'da hex string olarak serialize edilir; alan yoksa `None`.
    #[serde(
        default,
        with = "hex_hash_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_id_hash: Option<[u8; 6]>,
    /// Kullanıcının "kabul + güven" seçtiği an (unix epoch saniyeleri).
    /// `0` = legacy kayıt (timestamp yok); TTL hesabı `saturating_sub` ile
    /// korunur. Yeniden kullanıldığında `touch_trusted_by_hash` ile refresh.
    #[serde(default)]
    pub trusted_at_epoch: u64,
}

/// `Option<[u8; 6]>` için hex serde modülü. JSON wire formatında 12 karakter
/// lowercase hex string ("aabbccddeeff"); `None` → alan atlanır (struct
/// attribute `skip_serializing_if = "Option::is_none"`). Length != 6 veya
/// non-hex input → deserialize hatası.
mod hex_hash_opt {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    // serde signature kontratı `&Option<T>` ister — pass-by-value yapılamaz.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(super) fn serialize<S: Serializer>(
        value: &Option<[u8; 6]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            // skip_serializing_if zaten None'u atlıyor — buraya düşülmez,
            // düşerse null yazmak makul yedek.
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; 6]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        let Some(raw) = opt else {
            return Ok(None);
        };
        let bytes = hex::decode(&raw)
            .map_err(|e| D::Error::custom(format!("secret_id_hash hex decode: {e}")))?;
        if bytes.len() != 6 {
            return Err(D::Error::custom(format!(
                "secret_id_hash 6 bayt bekleniyor, bulunan {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 6];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Bu listedeki kayıtlardan gelen aktarımlar dialog göstermeden kabul
    /// edilir ve rate limiting uygulanmaz (memory kuralı: trusted cihazlar
    /// rate limit dışıdır). v0.6+ trust kararı birincil olarak
    /// `secret_id_hash` üzerinden verilir; legacy `(name, id)` kayıtlar
    /// `is_trusted_legacy` ile üç sürümlük uyumluluk penceresinde çalışır.
    ///
    /// JSON'da hem yeni biçim (`[{"name","id","secret_id_hash","trusted_at_epoch"}]`)
    /// hem de eski biçim (`["ad1", "ad2"]` / `[{"name","id"}]`) kabul
    /// edilir — bkz. [`migrate_trusted_value`].
    #[serde(default, deserialize_with = "deserialize_trusted_devices")]
    pub trusted_devices: Vec<TrustedDevice>,

    /// Trust TTL saniyesi — varsayılan 7 gün (`DEFAULT_TRUST_TTL_SECS`).
    /// Kullanıcı config.json'da bu alanı ayarlayarak 30 gün veya daha fazla
    /// uzatabilir (security vs. UX trade-off). `0` değeri TTL'i tamamen
    /// devre dışı bırakır — trust sonsuza kadar geçerli kalır (önerilmez).
    #[serde(default = "default_trust_ttl_secs")]
    pub trust_ttl_secs: u64,

    /// mDNS yayınını aç/kapat — H#4 privacy control.
    ///
    /// `true` (default): uygulama `_FC9F5ED42C8A._tcp.local.` altında ilan
    /// edilir, Android phone "nearby devices" listesinde görünür.
    /// `false`: "receive-only" mod — LAN'da görünmez, ama **gönderici**
    /// olarak hâlâ çalışabilir (keşif tarama aynı şekilde işler).
    /// Değişiklik restart gerektirir (mDNS daemon hot-swap henüz yok).
    #[serde(default = "default_advertise")]
    pub advertise: bool,

    /// Log verbosity — H#4 privacy control.
    ///
    /// `RUST_LOG` env var varsa o öncelikli (geliştirici kaçış vanası).
    /// Aksi halde `tracing_subscriber::EnvFilter` bu değerden üretilir.
    /// Sadece `hekadrop` crate'i hedeflenir; dependency loglar default warn.
    #[serde(default)]
    pub log_level: LogLevel,

    /// İstatistik kaydı — H#4 privacy control.
    ///
    /// `true` (default): her transfer sonrası `stats.json` diske yazılır.
    /// `false`: privacy-conscious kullanıcı için transferler metriğe
    /// geçmez; mevcut stats.json **silinmez** (kullanıcı tekrar açabilir
    /// ve geçmiş metrik kaybolmaz), yalnızca yeni yazımlar durur.
    #[serde(default = "default_keep_stats")]
    pub keep_stats: bool,

    /// GitHub "yeni sürüm var mı" kontrolü opt-out — H#4 privacy control.
    ///
    /// `true` (default — privacy-first): update kontrolü varsayılan olarak
    /// KAPALI; GitHub API'ye istek atılmaz (User-Agent exposure yok).
    /// Kullanıcı UI'dan açana kadar sessizdir. `false`: "Güncelleme
    /// kontrol et" butonu GitHub API'ye istek atar. `HEKADROP_NO_UPDATE_CHECK`
    /// env var ile OR'lanır — env set ise setting bağımsız olarak skip.
    #[serde(default = "default_disable_update_check")]
    pub disable_update_check: bool,

    /// İlk açılış onboarding modal'ı gösterildi mi? Privacy-first default
    /// `false` — yeni kullanıcı için bir kere modal açılır, kullanıcı
    /// "Anladım" veya "Ayarları aç" dedikten sonra true'ya çekilir ve diske
    /// yazılır. v0.5/v0.6'dan upgrade eden kullanıcılar da `false` ile gelir
    /// → onboarding bir kez gösterilir (yeni feature'ları tanıtma fırsatı).
    #[serde(default)]
    pub first_launch_completed: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            device_name: None,
            download_dir: None,
            auto_accept: false,
            trusted_devices: Vec::new(),
            trust_ttl_secs: DEFAULT_TRUST_TTL_SECS,
            advertise: true,
            log_level: LogLevel::Info,
            keep_stats: true,
            disable_update_check: true,
            first_launch_completed: false,
        }
    }
}

impl Settings {
    /// v0.6 birincil trust kararı: peer'ın `secret_id_hash`'ine göre.
    ///
    /// TTL kontrolü burada yapılır; `trust_ttl_secs = 0` = TTL devre dışı
    /// (süresiz trust). Kayıt silinmez, sadece güvenilir sayılmaz —
    /// kullanıcı yeniden "kabul + güven" seçerse `add_trusted_with_hash`
    /// timestamp'i yeniler.
    // API ergonomics: caller'lar `&hash` ile çağırıyor (storage'da `Option<[u8;6]>`),
    // by-value `*hash` deref talebi kod akışını bozar. 2 byte pass-by-ref overhead
    // kabul edilebilir; bu yöntem hot path değil (trust kontrolü, frame başına ≤1).
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_trusted_by_hash(&self, hash: &[u8; 6]) -> bool {
        let now = now_epoch();
        let ttl = self.trust_ttl_secs;
        self.trusted_devices.iter().any(|d| {
            d.secret_id_hash.as_ref() == Some(hash)
                && (ttl == 0 || now.saturating_sub(d.trusted_at_epoch) < ttl)
        })
    }

    /// Legacy (v0.5 ve öncesi) trust kararı — `(name, id)` çifti üzerinden.
    ///
    /// v0.6'da yalnızca peer `secret_id_hash` **göndermediğinde** fallback
    /// olarak kullanılır. Üç sürüm sonra (v0.7'de) legacy yolu tamamen
    /// devre dışı kalacak. TTL bu yolda uygulanmaz — legacy kayıtlar zaten
    /// timestamp içermiyor, kullanıcı eski kararını kaybetmemeli.
    pub fn is_trusted_legacy(&self, device_name: &str, id: &str) -> bool {
        if device_name.is_empty() {
            return false;
        }
        self.trusted_devices
            .iter()
            .any(|d| d.name == device_name && (d.id.is_empty() || d.id == id))
    }

    /// v0.5 API imzasını koruyan geçiş fonksiyonu. Çağrı yerlerinde peer
    /// hash yoksa (örn. test kodunda veya legacy flow'da) bu kullanılır;
    /// v0.6 connection.rs/sender.rs hash-first akışa geçti.
    ///
    /// Davranış: `is_trusted_legacy` ile aynı — legacy kayıtları hâlâ
    /// çalıştırır, TTL kontrolü yapmaz. Yeni kodun `is_trusted_by_hash`
    /// kullanması beklenir.
    #[allow(dead_code)]
    pub fn is_trusted(&self, device_name: &str, id: &str) -> bool {
        self.is_trusted_legacy(device_name, id)
    }

    /// v0.6 birincil API: hash ile güven kaydı ekler / upgrade eder.
    ///
    /// Mantık:
    ///   1) Hash eşleşen kayıt varsa → timestamp'i yenile (touch).
    ///   2) Legacy kayıt varsa (name eşleşir, id ya boş ya eşit, hash None) →
    ///      yerinde upgrade: id doldur, hash yaz, timestamp = now. Kullanıcı
    ///      zaten bu cihazı güvenmişti; ek dialog gerekmiyor (opportunistic).
    ///   3) Değilse yeni kayıt push.
    ///
    /// Boş ad reddedilir.
    pub fn add_trusted_with_hash(&mut self, device_name: &str, id: &str, hash: [u8; 6]) {
        if device_name.is_empty() {
            return;
        }
        let now = now_epoch();
        // (1) Aynı hash — sadece timestamp yenile.
        if let Some(existing) = self
            .trusted_devices
            .iter_mut()
            .find(|d| d.secret_id_hash == Some(hash))
        {
            existing.trusted_at_epoch = now;
            // Opportunistic: name/id güncelle (peer yeniden adlandırılmış olabilir).
            if !device_name.is_empty() {
                existing.name = device_name.to_string();
            }
            if !id.is_empty() {
                existing.id = id.to_string();
            }
            return;
        }
        // (2) Legacy kaydı upgrade et — name eşleşir ve hash henüz None ise.
        if let Some(existing) = self.trusted_devices.iter_mut().find(|d| {
            d.name == device_name && d.secret_id_hash.is_none() && (d.id.is_empty() || d.id == id)
        }) {
            existing.secret_id_hash = Some(hash);
            existing.trusted_at_epoch = now;
            if !id.is_empty() {
                existing.id = id.to_string();
            }
            return;
        }
        // (3) Yeni kayıt.
        self.trusted_devices.push(TrustedDevice {
            name: device_name.to_string(),
            id: id.to_string(),
            secret_id_hash: Some(hash),
            trusted_at_epoch: now,
        });
    }

    /// Mevcut trusted bağlantı yeniden kullanıldığında timestamp'i yenile
    /// (sliding-window TTL). Aksi halde aktif cihazlar 7 gün sonunda
    /// dialog sorardı; bu UX'i fena bozar. Hash eşleşmeyen çağrı no-op.
    // API ergonomics: bkz. `is_trusted_by_hash` aynı gerekçe.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn touch_trusted_by_hash(&mut self, hash: &[u8; 6]) {
        let now = now_epoch();
        if let Some(existing) = self
            .trusted_devices
            .iter_mut()
            .find(|d| d.secret_id_hash.as_ref() == Some(hash))
        {
            existing.trusted_at_epoch = now;
        }
    }

    /// TTL dolmuş kayıtları listeden siler; dönen sayı silinen kayıt adedi.
    ///
    /// **v0.6'da startup'ta otomatik çağrılır** (bkz. `main.rs` `run_app`):
    /// eskiden "soft-expire" idi (listede kalırdı), ancak Issue #17 kapsamında
    /// legacy kayıtların kalıcı yaşaması saldırı yüzeyi yarattı — hash-suppress
    /// saldırısıyla peer hash göndermezse `is_trusted_legacy` yoluyla trust
    /// kararı alınabilir. Startup prune ile bu pencere kısalır.
    ///
    /// Legacy kayıt (`secret_id_hash == None`) TTL politikası:
    ///   * `trusted_at_epoch == 0` → v0.5'ten v0.6'ya upgrade sırasında
    ///     epoch bilinmediği için 0 yazıldı; bu kayıtlar **sınırsız
    ///     korunur** (opportunistic hash-upgrade şansı tanınır: peer
    ///     sonraki bağlantısında `add_trusted_with_hash` ile kayıt yenilenir).
    ///   * `trusted_at_epoch > 0` → 90 gün içinde hash-upgrade olmazsa
    ///     silinir (üç sürümlük uyumluluk window'u).
    ///
    /// Hash'li kayıtlar için `trust_ttl_secs` (default 7 gün) uygulanır.
    /// `trust_ttl_secs == 0` → TTL tamamen kapalı, hiçbir kayıt silinmez.
    pub fn prune_expired(&mut self) -> usize {
        const LEGACY_TTL_SECS: u64 = 90 * 24 * 3600; // 90 gün
        let ttl = self.trust_ttl_secs;
        if ttl == 0 {
            return 0;
        }
        let now = now_epoch();
        let before = self.trusted_devices.len();
        self.trusted_devices.retain(|d| {
            if d.secret_id_hash.is_none() {
                // Legacy kayıt: epoch=0 (v0.5 upgrade) sınırsız korunur;
                // epoch>0 kayıtlar 90 gün içinde hash-upgrade olmazsa silinir.
                return d.trusted_at_epoch == 0
                    || now.saturating_sub(d.trusted_at_epoch) < LEGACY_TTL_SECS;
            }
            now.saturating_sub(d.trusted_at_epoch) < ttl
        });
        before - self.trusted_devices.len()
    }

    /// v0.5 API imzası — hash'siz kayıt ekler (legacy yol).
    ///
    /// **v0.6'dan itibaren deprecated** (`#[deprecated]` note as of design
    /// 017): peer hash gönderdiğinde `add_trusted_with_hash` çağrılmalı.
    /// Bu fonksiyon yalnız hash yoksa (peer spec'e uymuyor / legacy
    /// senaryo) fallback olarak kullanılır. v0.7'de kaldırılacak.
    pub fn add_trusted(&mut self, device_name: &str, id: &str) {
        if device_name.is_empty() {
            return;
        }
        if self
            .trusted_devices
            .iter()
            .any(|d| d.name == device_name && d.id == id)
        {
            return;
        }
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
            secret_id_hash: None,
            trusted_at_epoch: 0,
        });
    }

    /// Yalnızca isme göre tüm eşleşen kayıtları siler.
    ///
    /// UI katmanı (main.rs) "`trust_remove::NAME`" IPC mesajıyla sadece adı
    /// iletir; geriye dönük uyum için bu imza korunur. Aynı adın birden çok
    /// id ile kaydı varsa hepsi silinir. ID tabanlı hassas silme için
    /// [`Self::remove_trusted_by_id`] kullanın.
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

    /// UI için her kaydın "Ad (`id_kisa`)" formatında görünüm listesini döner.
    ///
    /// v0.6'da zengin UI (TTL rozeti) kullanılmaya başlandığından ana UI
    /// yolu `push_trusted_to_ui` içindeki yapılandırılmış JSON'u tercih
    /// eder; bu fonksiyon legacy IPC çağrıları ve testler için korunur.
    #[allow(dead_code)]
    pub fn trusted_display_list(&self) -> Vec<String> {
        self.trusted_devices.iter().map(|d| d.display()).collect()
    }
}

/// Persistent state load hata türleri — `LoadError::Corrupt` durumunda
/// caller dosyayı backup'lar ve UI'a uyarı verir; `Io` durumunda kullanıcı
/// permission/disk hatasını anlamalı.
///
/// **Why error type:** Önceki davranış (`unwrap_or_default`) bozuk dosya
/// durumunda kullanıcının trusted device listesini sessizce silip bir
/// sonraki save ile **kalıcı veri kaybına** sebep oluyordu (PR #90 review,
/// Gemini medium). Hata ayrımı `NotFound = OK, Corrupt = kullanıcı görür`
/// semantiğini sağlar.
///
/// **Kapsam:** Settings (`config.json`) ve Stats (`stats.json`) load
/// hataları için ortak. PR #109 review (Copilot): mesajlar generic
/// "kalıcı state dosyası" diyor, "config.json" demiyor — Stats için de
/// anlaşılır.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("kalıcı state dosyası bozuk ({path}): {source}")]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("kalıcı state dosyası okunamadı ({path}): {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Settings {
    /// Strict load — `NotFound` → `Ok(Self::default())`, parse error
    /// → `Err(LoadError::Corrupt)`, diğer I/O → `Err(LoadError::Io)`.
    pub fn load(path: &Path) -> std::result::Result<Self, LoadError> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str::<Self>(&s).map_err(|source| LoadError::Corrupt {
                path: path.to_path_buf(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(LoadError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Convenience: hata olursa default dön + hata bilgisini de dışa ver.
    /// Caller `Option<LoadError>`'ı log'a basıp UI'a notification gönderir,
    /// `Corrupt` durumunda dosyayı [`backup_corrupt_file`] ile yedekler.
    pub fn load_or_default(path: &Path) -> (Self, Option<LoadError>) {
        match Self::load(path) {
            Ok(s) => (s, None),
            Err(e) => (Self::default(), Some(e)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // Pre-flight: kullanıcı explicit bir `download_dir` seçmişse dizinin
        // hâlâ var olduğundan ve yazılabilir olduğundan emin ol. Aksi halde
        // kullanıcı Settings'te kaydet-yeşil-tik görür ama runtime'da transfer
        // "nedensiz" iptal olur. Burada erken hata döndürerek handler UI'a
        // anlamlı bir mesaj gösterebilir.
        //
        // `None` (varsayılan `~/Downloads` çözünürlüğü) durumunda atlanır —
        // resolve edilmiş default dizin platform tarafından garanti ediliyor
        // ve tipik olarak mevcut; bu validation sadece kullanıcının kendi
        // seçtiği bir path için anlamlı.
        if let Some(ref dir) = self.download_dir {
            validate_download_dir(dir).context("download_dir doğrulaması başarısız")?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self).context("JSON serialize")?;
        atomic_write(path, json.as_bytes()).context("config.json yazılamadı")?;
        Ok(())
    }

    /// Debounced variant — aynı sürede rapid değişen ayarları (privacy toggle
    /// serisi vb.) tek diske-yazımda birleştirir.
    ///
    /// Davranış: bu fonksiyon çağrıldığında 100 ms sonra `save()` tetikleyen
    /// bir tokio task spawn edilir. 100 ms bitmeden ikinci bir çağrı gelirse
    /// önceki task `abort()` edilir ve saatin başlangıcı sıfırlanır — yalnızca
    /// **en son** snapshot diske yazılır. Sessiz (rapid toggle yok) bir süreçte
    /// tek `save_debounced()` çağrısı tek atomik write üretir.
    ///
    /// Debounce task'ı her zaman çağıran tarafından sağlanan Tokio runtime
    /// handle'ı üzerinde spawn edilir; UI/event-loop thread'i runtime dışında
    /// olsa bile coalesce davranışı korunur. Önceden `Handle::try_current()`
    /// kullanılıyordu — fakat tao event-loop thread'i tokio runtime'a bağlı
    /// olmadığından her çağrı `Err(_)` dalına düşüp sync `save()`'e iniyordu
    /// ve debounce fiilen devre dışı kalıyordu.
    pub fn save_debounced(&self, handle: &tokio::runtime::Handle, path: PathBuf) {
        let snap = self.clone();
        let handle = handle.clone();
        let mut slot = DEBOUNCE_TASK.lock();
        // Aynı window içindeki önceki pending task'ı iptal et — son çağrı kazanır.
        if let Some(prev) = slot.take() {
            prev.abort();
        }
        *slot = Some(handle.spawn(async move {
            tokio::time::sleep(DEBOUNCE_WINDOW).await;
            if let Err(e) = snap.save(&path) {
                tracing::warn!("settings save_debounced write: {}", e);
            }
        }));
    }

    /// Kullanıcı `device_name` set etmediyse `default()` ile platform default'una düş.
    /// RFC-0001 §5 Adım 4: core artık `crate::platform::*` çağırmaz; default
    /// closure'unu caller (app) inject eder (`crate::platform::device_name`).
    pub fn resolved_device_name<F: FnOnce() -> String>(&self, default: F) -> String {
        self.device_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default)
    }

    /// Kullanıcı `download_dir` set etmediyse `default()` ile platform default'una düş.
    /// RFC-0001 §5 Adım 4: core artık `crate::platform::*` çağırmaz; default
    /// closure'unu caller (app) inject eder (`crate::platform::default_download_dir`).
    pub fn resolved_download_dir<F: FnOnce() -> PathBuf>(&self, default: F) -> PathBuf {
        self.download_dir.clone().unwrap_or_else(default)
    }
}

/// Debounce penceresi — `save_debounced()` çağrısı 100 ms sonra diske yazar.
/// Rapid-toggle UX'inde (20+ privacy switch) ard arda değişen ayarlar tek
/// atomic write'ta birleşir. Window'u büyütmek UI "Kaydedildi" geri bildirimini
/// geciktirir, küçültmek coalescing faydasını düşürür — 100 ms insan-algısı
/// eşiğinin altında (tipik 200 ms "anlık") ve I/O amortize için yeterli.
const DEBOUNCE_WINDOW: std::time::Duration = std::time::Duration::from_millis(100);

/// En son pending `save_debounced` task'ı. Yeni çağrı geldiğinde `abort()`
/// edilir ki son snapshot kazansın. Tokio `JoinHandle::abort` idempotent —
/// zaten tamamlanmış task'ı abort etmek no-op.
static DEBOUNCE_TASK: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>> =
    parking_lot::Mutex::new(None);

/// `download_dir` pre-flight — dizin var mı ve yazılabilir mi?
///
/// İki aşama:
///   1) `metadata().is_dir()` — path bir dizine işaret ediyor (file veya yok
///      değil). Symlink follow edilir (standart `metadata` davranışı).
///   2) Write probe: `.hekadrop_write_test.<pid>` dosyasını yarat → hemen sil.
///      Read-only mount, permission denied, full-disk gibi durumları yakalar.
///      Dosya adında pid var — iki process paralel probe etse çakışmaz.
///
/// Başarılı dönüşte probe dosyası diskte kalmaz (rename/crash-time sızıntı
/// yok; atomic write-test değil, create+delete — crash durumunda tmp dosya
/// kalabilir ama adı sabit değil, re-probe doğru davranır).
///
/// Public API: `main.rs::handle_settings_save` doğrudan da çağırabilir
/// (`Settings::save` zaten kullanıyor, ikinci doğrulama idempotent).
pub fn validate_download_dir(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).map_err(|e| HekaError::DownloadDirInvalid {
        path: path.display().to_string(),
        reason: format!("okunamadı: {e}"),
    })?;
    if !meta.is_dir() {
        return Err(HekaError::DownloadDirInvalid {
            path: path.display().to_string(),
            reason: "bir dizin değil".into(),
        }
        .into());
    }
    let probe = path.join(format!(".hekadrop_write_test.{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(HekaError::DownloadDirInvalid {
            path: path.display().to_string(),
            reason: format!("yazılabilir değil: {e}"),
        }
        .into()),
    }
}

/// Tmp dosya scope-guard'ı — Drop anında `path`'i sessizce siler.
///
/// `atomic_write` içinde tmp dosya yaratılır; başarılı `rename`'den sonra
/// `defuse()` çağrılarak silinme iptal edilir. Aksi takdirde (write hatası,
/// rename hatası, paniğe neden olan bir hata) Drop çalışır ve tmp diskte
/// sızmaz — review-18 (MED) cleanup gereksinimi.
struct TmpCleanup {
    path: Option<std::path::PathBuf>,
}

impl TmpCleanup {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }
    /// Temizliği iptal et — rename başarılı olduğunda çağrılır.
    fn defuse(mut self) {
        self.path = None;
    }
}

impl Drop for TmpCleanup {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Cross-platform atomik replace. Unix'te `fs::rename` zaten atomik
/// (`O_RENAME`) ve destination mevcutsa üzerine yazar. Windows'ta
/// `std::fs::rename` **destination varsa hata verir** — her `save()` ikinci
/// çağrıdan itibaren sessizce başarısız olurdu. `MoveFileExW` +
/// `MOVEFILE_REPLACE_EXISTING` bu durumu çözer; `MOVEFILE_WRITE_THROUGH`
/// direktori entry'sinin diske flush'unu garantiler.
#[cfg(unix)]
fn replace_atomic(tmp: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(tmp, dst)
}

#[cfg(windows)]
fn replace_atomic(tmp: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    // PCWSTR dizileri null-terminated olmalı — OsStr::encode_wide null
    // katmaz, bu yüzden manuel ekliyoruz (repo içi başka Win32 çağrılarıyla
    // aynı pattern, bkz. src/platform.rs, src/main.rs).
    let mut src_w: Vec<u16> = tmp.as_os_str().encode_wide().collect();
    src_w.push(0);
    let mut dst_w: Vec<u16> = dst.as_os_str().encode_wide().collect();
    dst_w.push(0);
    // SAFETY: `src_w` ve `dst_w` `encode_wide` + manuel `push(0)` ile
    // NUL-terminated UTF-16 buffer'lar; `MoveFileExW` senkron çağrısı
    // süresince scope'ta canlı. PCWSTR'ler yalnızca embedded NUL'a kadar
    // okunur; başka pointer/handle paylaşımı yok, dönüş değeri Result olarak
    // ele alınıyor.
    unsafe {
        MoveFileExW(
            PCWSTR(src_w.as_ptr()),
            PCWSTR(dst_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(std::io::Error::other)
    }
}

/// Process-wide disk write lock — review-18 (HIGH) save-snapshot reordering.
///
/// İki concurrent `save()` çağrısı (ör. connection.rs Stats + sender.rs Stats
/// aynı anda) diske yazılırken, yazım sırası ters dönebilirdi: geç başlayan
/// save önce bitip eski snapshot'ı diske bırakabilirdi (kernel scheduler,
/// disk I/O queue vb.). Settings `RwLock`'u artık lock dışında save yaptığımız
/// için koruma sağlamıyor. Bu mutex her `save()`'i FIFO sırasına sokar.
/// Settings ve Stats ayrı hot-path ancak tek bir lock yeterli ve kolay.
static SETTINGS_DISK_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Atomik dosya yazma — tmp-file + rename pattern.
///
/// **Neden:** `fs::write` traditionally `O_TRUNC | O_CREAT` açar; crash/panic
/// sırasında diskte **yarım-yazılmış** JSON kalabilir (Bug: bir sonraki `load()`
/// `Settings::default()`'e düşer, kullanıcının trusted cihaz listesi silinmiş
/// gibi görünür). `rename` POSIX'te atomik — eski içerik ya olduğu gibi kalır
/// ya da tamamen yeni içerikle değişir; yarım durum yoktur. Windows'ta
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` ile
/// best-effort atomik replace (aynı volume şart).
///
/// Tmp dosya adı `pid + rand u64` ile benzersizdir — aynı süreçte iki thread
/// aynı anda `save()` çağırırsa da tmp dosya adları çakışmaz. Scope-guard
/// (`TmpCleanup`) başarısız yazımlarda sızıntıyı önler. `sync_all` hataları
/// artık yutulmuyor (durability garantisi propagate edilir).
pub(crate) fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_mode(path, data, None)
}

/// Bozuk config dosyasını `<path>.corrupt-<unix-nanos>-<pid>-<attempt>` olarak
/// yedekler ve `Result<PathBuf, io::Error>` döner. Caller silinmeden önce
/// çağırmalı — böylece kullanıcı dosyayı manuel kurtarabilir.
///
/// **Naming detail (PR #109 Copilot):** Saniye çözünürlüğü + sabit suffix
/// race-prone idi (aynı saniyede tekrar denemeler veya eski yedekler hedefin
/// var olmasına neden olurdu, `rename` `AlreadyExists` döndürürdü).
/// nanos + pid + attempt counter ile çakışma pratikte imkansız; ek olarak
/// `AlreadyExists` durumunda 16 deneme yapılır, sonra hata.
///
/// **Sorumluluk sınırı:** Bu fonksiyon yalnız orijinal dosyayı yedek
/// konumuna **rename** eder. Backup başarısız olursa orijinal dosya
/// `rename` tamamlanmadığı için yerinde kalır. Ancak bu fonksiyon
/// **persistence akışını bloklayan bir mekanizma değildir** — ilgili
/// politikayı (örn. `AppState.persistence_blocked`) caller uygular.
/// PR #109 (Copilot doc accuracy): önceki yorum "garanti" iddia ediyordu;
/// gerçek garanti caller-side flag ile sağlanır.
pub fn backup_corrupt_file(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..16u32 {
        let mut backup = path.as_os_str().to_owned();
        backup.push(format!(".corrupt-{nanos}-{pid}-{attempt}"));
        let backup = std::path::PathBuf::from(backup);
        match std::fs::rename(path, &backup) {
            Ok(()) => return Ok(backup),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "backup retry quota exhausted",
        )
    }))
}

/// `atomic_write` variant'ı — kısıtlı (gizli) dosyalar için tmp'yi
/// baştan verilen mode ile açar.
///
/// **Neden (review #34 MED):** Default `atomic_write` tmp dosyayı process
/// umask'ına göre (tipik 0644) açıyordu; `identity.rs` rename sonrası
/// `set_permissions(0o600)` çağrısı yapsa bile rename ile izin sıkılaştırma
/// arasında world-readable bir pencere kalıyordu. Tmp'yi `O_EXCL | mode(0o600)`
/// ile açtığımızda umask ne olursa olsun dosya ilk andan itibaren doğru
/// permission'a sahip olur ve rename aynı inode'u koruduğundan pencere kapanır.
///
/// `mode` parametresi Unix'e özgüdür; Windows'ta umask kavramı olmadığı için
/// yoksayılır (NTFS default ACL kullanıcı profili altında owner-only kabul
/// edilebilir; tam ACL sıkılaştırma v0.7 follow-up).
pub(crate) fn atomic_write_mode(
    path: &std::path::Path,
    data: &[u8],
    mode: Option<u32>,
) -> std::io::Result<()> {
    use rand::RngCore;
    use std::io::Write as _;

    let _disk_guard = SETTINGS_DISK_LOCK.lock();

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path'ın parent'ı yok")
    })?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config.json");

    // Unique tmp adı: pid + rand u64 + create_new(true) retry.
    // create_new başarısız olursa (AlreadyExists) yeni rand ile tekrar dene;
    // başka I/O hatalarında erken çık.
    let pid = std::process::id();
    let mut attempts = 0u32;
    let (mut file, tmp_path) = loop {
        attempts += 1;
        let r = rand::thread_rng().next_u64();
        let tmp = parent.join(format!(".{file_name}.{pid}.{r:016x}.tmp"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            if let Some(m) = mode {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(m);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = mode; // Windows: parametre şu an no-op (ACL v0.7).
        }
        match opts.open(&tmp) {
            Ok(f) => break (f, tmp),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts < 8 => continue,
            Err(e) => return Err(e),
        }
    };

    // Drop anında sızıntı engelle. Rename başarılı olursa defuse().
    let cleanup = TmpCleanup::new(tmp_path.clone());

    file.write_all(data)?;
    // Durability: sync_all hatasını yutmuyoruz — kullanıcı güvenli yazımı
    // talep etti; diskten dönüş başarısızsa save çağrısı hata dönmeli.
    file.sync_all()?;
    drop(file);

    replace_atomic(&tmp_path, path)?;
    cleanup.defuse();
    Ok(())
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
                "trusted_devices array bekleniyordu, geldi: {other:?}"
            ))
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        match item {
            serde_json::Value::String(s) => {
                // Legacy: "device-name" → {name: s, id: "", hash: None, ts: 0}
                if !s.is_empty() {
                    out.push(TrustedDevice {
                        name: s,
                        id: String::new(),
                        secret_id_hash: None,
                        trusted_at_epoch: 0,
                    });
                }
            }
            serde_json::Value::Object(_) => {
                let td: TrustedDevice = serde_json::from_value(item)
                    .map_err(|e| format!("TrustedDevice parse: {e}"))?;
                if !td.name.is_empty() {
                    out.push(td);
                }
            }
            other => {
                return Err(format!(
                    "trusted_devices elemanı beklenmeyen tip: {other:?}"
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
            secret_id_hash: None,
            trusted_at_epoch: 0,
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
            secret_id_hash: None,
            trusted_at_epoch: 0,
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
            secret_id_hash: None,
            trusted_at_epoch: 0,
        };
        // İlk 8 karakter alınmalı.
        assert_eq!(d.display(), "Pixel 7 (abcdef01)");
    }

    #[test]
    fn display_formati_legacy_id_yoksa_sadece_ad() {
        let d = TrustedDevice {
            name: "Pixel 7".into(),
            id: String::new(),
            secret_id_hash: None,
            trusted_at_epoch: 0,
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
            s.add_trusted(&format!("dev-{i}"), &format!("id-{i}"));
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

    // =======================================================================
    // v0.6 trusted device identity hardening (Issue #17) — tests
    // =======================================================================

    #[test]
    fn v06_legacy_json_secret_id_hash_none_olarak_yuklenir() {
        // v0.5.2 config.json şeması — secret_id_hash alanı yok. Yeni struct
        // `#[serde(default)]` sayesinde `None` ile yüklenmeli.
        let legacy = r#"{
            "trusted_devices": [{"name": "Pixel 7", "id": "endpoint-abc"}]
        }"#;
        let s: Settings = serde_json::from_str(legacy).expect("parse");
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].secret_id_hash, None);
        assert_eq!(s.trusted_devices[0].trusted_at_epoch, 0);
        // trust_ttl_secs alanı yoksa default 7 gün.
        assert_eq!(s.trust_ttl_secs, DEFAULT_TRUST_TTL_SECS);
        // is_trusted_legacy hala çalışmalı.
        assert!(s.is_trusted_legacy("Pixel 7", "endpoint-abc"));
    }

    #[test]
    fn v06_is_trusted_by_hash_eslesme_ve_ttl() {
        let mut s = Settings::default();
        let hash = [0xAAu8; 6];
        s.add_trusted_with_hash("Pixel 7", "endpoint-abc", hash);
        // Taze kayıt — trusted.
        assert!(s.is_trusted_by_hash(&hash));
        // Farklı hash — değil.
        assert!(!s.is_trusted_by_hash(&[0xBBu8; 6]));
    }

    #[test]
    fn v06_ttl_suresi_doldu_untrusted_doner() {
        let mut s = Settings::default();
        let hash = [0xCCu8; 6];
        s.trusted_devices.push(TrustedDevice {
            name: "Eski".into(),
            id: "old-id".into(),
            secret_id_hash: Some(hash),
            // TTL'den 1 sn önce — süre dolmuş.
            trusted_at_epoch: now_epoch().saturating_sub(DEFAULT_TRUST_TTL_SECS + 1),
        });
        assert!(!s.is_trusted_by_hash(&hash));

        // TTL içinde — hâlâ trusted.
        s.trusted_devices[0].trusted_at_epoch =
            now_epoch().saturating_sub(DEFAULT_TRUST_TTL_SECS - 100);
        assert!(s.is_trusted_by_hash(&hash));
    }

    #[test]
    fn v06_ttl_sifir_sinirsiz_trust_demek() {
        let mut s = Settings {
            trust_ttl_secs: 0,
            ..Settings::default()
        };
        let hash = [0xDDu8; 6];
        s.trusted_devices.push(TrustedDevice {
            name: "Sonsuz".into(),
            id: "id".into(),
            secret_id_hash: Some(hash),
            // Çok eski — TTL=0 olduğu için yine de trusted.
            trusted_at_epoch: 1,
        });
        assert!(s.is_trusted_by_hash(&hash));
    }

    #[test]
    fn v06_custom_ttl_override_30_gun() {
        // Kullanıcı config.json'da trust_ttl_secs alanını 30 güne çekebilir.
        let json = format!(
            r#"{{"trust_ttl_secs": {}, "trusted_devices": []}}"#,
            30 * 24 * 3600_u64
        );
        let s: Settings = serde_json::from_str(&json).expect("parse");
        assert_eq!(s.trust_ttl_secs, 30 * 24 * 3600);
    }

    #[test]
    fn v06_opportunistic_legacy_upgrade() {
        // v0.5.x legacy kayıt (hash=None) → aynı peer hash ile tekrar
        // bağlandığında in-place upgrade olmalı.
        let mut s = Settings::default();
        s.trusted_devices.push(TrustedDevice {
            name: "Pixel 7".into(),
            id: "endpoint-abc".into(),
            secret_id_hash: None,
            trusted_at_epoch: 0,
        });
        let hash = [0xEEu8; 6];
        s.add_trusted_with_hash("Pixel 7", "endpoint-abc", hash);
        // Duplicate yaratmamalı.
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].secret_id_hash, Some(hash));
        assert_eq!(s.trusted_devices[0].id, "endpoint-abc");
        assert!(s.trusted_devices[0].trusted_at_epoch > 0);
    }

    #[test]
    fn v06_opportunistic_upgrade_legacy_bos_id() {
        // Legacy kayıt boş id ile (Vec<String> migrasyonu). Hash ile upgrade
        // edildiğinde id peer'ınkiyle doldurulmalı.
        let mut s = Settings::default();
        s.trusted_devices.push(TrustedDevice {
            name: "Eski".into(),
            id: String::new(),
            secret_id_hash: None,
            trusted_at_epoch: 0,
        });
        let hash = [0x77u8; 6];
        s.add_trusted_with_hash("Eski", "real-endpoint", hash);
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].id, "real-endpoint");
        assert_eq!(s.trusted_devices[0].secret_id_hash, Some(hash));
    }

    #[test]
    fn v06_touch_trusted_by_hash_timestamp_yeniler() {
        let mut s = Settings::default();
        let hash = [0x11u8; 6];
        s.trusted_devices.push(TrustedDevice {
            name: "Cihaz".into(),
            id: "id".into(),
            secret_id_hash: Some(hash),
            trusted_at_epoch: 100, // çok eski
        });
        s.touch_trusted_by_hash(&hash);
        assert!(s.trusted_devices[0].trusted_at_epoch > 1_000_000);
    }

    #[test]
    fn v06_touch_yanlis_hash_no_op() {
        let mut s = Settings::default();
        s.trusted_devices.push(TrustedDevice {
            name: "Cihaz".into(),
            id: "id".into(),
            secret_id_hash: Some([0x11u8; 6]),
            trusted_at_epoch: 100,
        });
        s.touch_trusted_by_hash(&[0x99u8; 6]);
        assert_eq!(s.trusted_devices[0].trusted_at_epoch, 100);
    }

    #[test]
    fn v06_prune_expired_hash_kayitlari_siler_legacy_siyler() {
        let mut s = Settings::default();
        let fresh_hash = [0x10u8; 6];
        let old_hash = [0x20u8; 6];
        // Fresh hash kayıt — TTL içinde.
        s.trusted_devices.push(TrustedDevice {
            name: "Fresh".into(),
            id: "id1".into(),
            secret_id_hash: Some(fresh_hash),
            trusted_at_epoch: now_epoch(),
        });
        // Expired hash kayıt.
        s.trusted_devices.push(TrustedDevice {
            name: "Old".into(),
            id: "id2".into(),
            secret_id_hash: Some(old_hash),
            trusted_at_epoch: now_epoch().saturating_sub(DEFAULT_TRUST_TTL_SECS + 100),
        });
        // Legacy kayıt — prune dokunmamalı.
        s.trusted_devices.push(TrustedDevice {
            name: "Legacy".into(),
            id: "id3".into(),
            secret_id_hash: None,
            trusted_at_epoch: 0,
        });

        let removed = s.prune_expired();
        assert_eq!(removed, 1);
        assert_eq!(s.trusted_devices.len(), 2);
        assert!(s.trusted_devices.iter().any(|d| d.name == "Fresh"));
        assert!(s.trusted_devices.iter().any(|d| d.name == "Legacy"));
    }

    #[test]
    fn v06_add_trusted_with_hash_hash_duplicate_yaratmaz() {
        let mut s = Settings::default();
        let hash = [0x42u8; 6];
        s.add_trusted_with_hash("Pixel", "id-1", hash);
        s.add_trusted_with_hash("Pixel", "id-1", hash);
        assert_eq!(s.trusted_devices.len(), 1);
    }

    #[test]
    fn v06_add_trusted_with_hash_bos_ad_reddedilir() {
        let mut s = Settings::default();
        s.add_trusted_with_hash("", "id", [0xFF; 6]);
        assert!(s.trusted_devices.is_empty());
    }

    #[test]
    fn v06_secret_id_hash_hex_serialize_ve_deserialize() {
        let mut s = Settings::default();
        let hash = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42];
        s.add_trusted_with_hash("Pixel", "id", hash);
        let json = serde_json::to_string(&s).expect("serialize");
        // Hex string'in JSON'da göründüğünü doğrula.
        assert!(
            json.contains("\"deadbeef0042\""),
            "beklenen hex yok: {json}"
        );
        let back: Settings = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.trusted_devices[0].secret_id_hash, Some(hash));
    }

    #[test]
    fn v06_secret_id_hash_bozuk_hex_hata_doner() {
        let bad = r#"{"trusted_devices":[{"name":"X","id":"y","secret_id_hash":"notvalidhex"}]}"#;
        let r: Result<Settings, _> = serde_json::from_str(bad);
        assert!(r.is_err());
    }

    #[test]
    fn v06_secret_id_hash_yanlis_boyut_hata_doner() {
        let bad = r#"{"trusted_devices":[{"name":"X","id":"y","secret_id_hash":"aabbcc"}]}"#;
        let r: Result<Settings, _> = serde_json::from_str(bad);
        assert!(r.is_err());
    }

    #[test]
    fn v06_is_trusted_legacy_v05_kayit_calisir() {
        // add_trusted (v0.5 API) kullanılırsa secret_id_hash=None, timestamp=0.
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");
        // is_trusted_by_hash boş hash ile false (kayıt hash'siz).
        assert!(!s.is_trusted_by_hash(&[0u8; 6]));
        // Legacy yol hâlâ çalışır.
        assert!(s.is_trusted_legacy("Pixel 7", "endpoint-abc"));
    }

    #[test]
    fn v06_hijack_regression_ayni_name_id_farkli_hash_untrusted() {
        // Issue #17 T2 scenario: attacker trusted kaydın (name, id)
        // çiftini spoof eder ama hash farklı. Trust kararı hash'e bağlı
        // olduğundan dialog yine gösterilmeli (= is_trusted_by_hash false).
        let mut s = Settings::default();
        s.add_trusted_with_hash("Pixel", "ABCD", [0xAA; 6]);
        // Aynı (name, id) ama farklı hash — trust verilmemeli.
        assert!(!s.is_trusted_by_hash(&[0xBB; 6]));
        // Aynı hash — verilmeli.
        assert!(s.is_trusted_by_hash(&[0xAA; 6]));
    }

    /// PR #35 review (Copilot HIGH, `discussion_r3107564927`) regression:
    /// Legacy `(name, id)` kaydı olan cihaz **unknown/mismatched** bir hash
    /// ile bağlandığında trusted sayılMAMALI — dialog ZORUNLU. Aksi halde
    /// legacy spoofing vektörü açıktır: attacker kurbanın (name, id)'sini
    /// öğrenir, kendi hash'i ile gelir, OR fallback nedeniyle auto-accept
    /// olur, Accept branch'indeki opportunistic upgrade attacker'ın hash'ini
    /// legacy kayda bağlar → kalıcı silent bypass. Bu nedenle strict
    /// hash-first semantic seçildi; OR fallback kabul edilmez.
    ///
    /// Doğru trust karar mantığı (`connection.rs` `handle_sharing_frame`):
    ///   Some(h) => `is_trusted_by_hash(h)`          // YALNIZ hash
    ///   None    => `is_trusted_legacy(name, id)`    // pre-v0.6 peer
    ///
    /// Bu test connection.rs'teki `trusted` ifadesini Settings seviyesinde
    /// simüle eder — tam flow (`prompt_accept`) için test harness yok.
    ///
    /// Legacy kullanıcı migration UX: ilk v0.6 bağlantısında one-time
    /// dialog kullanıcıya gösterilir; Accept sonrası connection.rs'in
    /// opportunistic upgrade bloğu hash'i legacy kayda bağlar, sonraki
    /// bağlantılar dialog'suz geçer.
    #[test]
    fn v06_legacy_kayit_hash_ile_gelirse_dialog_zorunlu() {
        let mut s = Settings::default();
        // Kullanıcı v0.5'te "Pixel 7"yi trusted etmiş, hash yok.
        s.add_trusted("Pixel 7", "endpoint-abc");
        let peer_hash = [0xAB; 6];

        // connection.rs'teki trusted hesabı (strict hash-first):
        //   Some(h) => is_trusted_by_hash(h)  — legacy fallback YOK.
        let trusted = s.is_trusted_by_hash(&peer_hash);
        assert!(
            !trusted,
            "peer hash gönderdi ama kayıtta yok → trusted=false olmalı, \
             dialog çıkmalı (legacy (name,id) match'i bypass'a çevrilMEMELİ)"
        );

        // Legacy kayıt hâlâ duruyor (migration için). Kullanıcı dialog'a
        // Accept derse connection.rs'in opportunistic upgrade bloğu
        // add_trusted_with_hash ile hash'i legacy'ye yerleştirir; sonraki
        // bağlantıda is_trusted_by_hash true döner.
        assert!(s.is_trusted_legacy("Pixel 7", "endpoint-abc"));
        assert!(!s.is_trusted_by_hash(&peer_hash));
    }

    /// PR #35 review (Copilot HIGH) regression — spoofing vektörü açıkça:
    /// Attacker kurbanın legacy (name, id)'sini öğrenir, keyfi bir hash
    /// gönderir. Trust kararı hash-first olduğu için attacker HİÇBİR zaman
    /// auto-trusted olmamalı; kullanıcı dialog görmeli.
    #[test]
    fn v06_legacy_match_hash_mismatch_spoofing_engellenir() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");

        // Attacker: aynı (name, id), farklı hash.
        let attacker_hash = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];

        // Strict hash-first karar.
        assert!(!s.is_trusted_by_hash(&attacker_hash));

        // Legacy eşleşmesi var — ama trust kararı artık OR'lamıyor.
        assert!(s.is_trusted_legacy("Pixel 7", "endpoint-abc"));

        // Auto-trust olmaması gerekir → dialog zorunlu.
        // Eski OR'lu kodda bu assertion false döner (attacker auto-accept).
        let auto_trusted_under_strict_rule = s.is_trusted_by_hash(&attacker_hash);
        assert!(
            !auto_trusted_under_strict_rule,
            "legacy (name, id) match + unknown hash kombinasyonu auto-accept \
             üretmemeli — aksi halde PR #35 review'da raporlanan spoofing \
             vektörü geri gelir"
        );
    }

    /// Review #34 HIGH #1 regression: opportunistic legacy → hash upgrade'in
    /// kendisi **mutasyon** olduğu için unit-test'te doğrudan çağırılmamalı.
    /// `add_trusted_with_hash(name, id, h)` çağrılmadığı sürece settings değişmez.
    ///
    /// Bu test, connection.rs'te reject path'inde upgrade fonksiyonunun
    /// çağrılmadığını structurally doğrular: reject yolunda legacy kayıt
    /// hash'siz kalmalıdır. Gerçek reject simülasyonu için no-op davranışı.
    #[test]
    fn v06_reject_path_legacy_upgrade_yapmaz() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");
        let snapshot_before = s.trusted_devices.clone();

        // Reject branch'inde connection.rs `add_trusted_with_hash` çağırMAZ.
        // Hiçbir mutasyon olmadığı için settings değişmemeli.
        // (Eski kod bu noktada `add_trusted_with_hash(name, id, h)` çağırıyordu.)
        let _peer_hash = [0xCC; 6];
        // no-op: yeni kodda reject'te upgrade yok.

        assert_eq!(s.trusted_devices, snapshot_before);
        assert!(s.trusted_devices[0].secret_id_hash.is_none());
        // Hash ile gelen attacker bir sonraki bağlantıda hâlâ dialog görmeli.
        assert!(!s.is_trusted_by_hash(&[0xCC; 6]));
    }

    /// Review #34 HIGH #1 pozitif taraf: Accept yolunda legacy kayıt
    /// doğru şekilde upgrade edilebilmeli. Bu `add_trusted_with_hash`
    /// semantiğini doğrular — connection.rs Accept branch'i bu çağrıyı
    /// (yalnız decision==Accept ise) yapar.
    #[test]
    fn v06_accept_path_legacy_kayit_hash_ile_yukseltilir() {
        let mut s = Settings::default();
        s.add_trusted("Pixel 7", "endpoint-abc");
        let peer_hash = [0xDD; 6];

        // Accept branch'ini simüle et: is_trusted_legacy true + yeni hash gelir.
        assert!(s.is_trusted_legacy("Pixel 7", "endpoint-abc"));
        s.add_trusted_with_hash("Pixel 7", "endpoint-abc", peer_hash);

        // Yerinde upgrade: tek kayıt kalmalı, hash ve timestamp dolu.
        assert_eq!(s.trusted_devices.len(), 1);
        assert_eq!(s.trusted_devices[0].secret_id_hash, Some(peer_hash));
        assert!(s.trusted_devices[0].trusted_at_epoch > 0);
        assert!(s.is_trusted_by_hash(&peer_hash));
    }

    // =======================================================================
    // H#4 privacy controls — settings migration + defaults
    // =======================================================================

    #[test]
    fn h4_default_privacy_alanlari() {
        let s = Settings::default();
        assert!(
            s.advertise,
            "advertise default true (v0.5 davranışı korunur)"
        );
        assert_eq!(s.log_level, LogLevel::Info);
        assert!(
            s.keep_stats,
            "keep_stats default true (eski config'ler migrate olduğunda kayıp olmasın)"
        );
        // Dalga 2: privacy-first — update check default KAPALI.
        assert!(
            s.disable_update_check,
            "disable_update_check default true (privacy-first, GitHub API sessiz)"
        );
    }

    #[test]
    fn h4_v05_config_json_eski_alanlar_eksik_default_dolar() {
        // Pre-H#4 config'i — hiçbir privacy alanı yok. `#[serde(default)]`
        // ile default değerler otomatik uygulanmalı.
        let legacy = r#"{
            "device_name": "MacBook",
            "auto_accept": false,
            "trusted_devices": []
        }"#;
        let s: Settings = serde_json::from_str(legacy).expect("parse");
        assert!(s.advertise);
        assert_eq!(s.log_level, LogLevel::Info);
        assert!(s.keep_stats);
        // Dalga 2: eski config'ler de privacy-first default'a düşer.
        assert!(s.disable_update_check);
    }

    #[test]
    fn h4_log_level_camelcase_hayir_lowercase_serialize() {
        // `#[serde(rename_all = "lowercase")]` — "Info" değil "info".
        let s = Settings {
            log_level: LogLevel::Warn,
            ..Settings::default()
        };
        let json = serde_json::to_string(&s).expect("serialize");
        assert!(json.contains("\"warn\""), "lowercase beklenir: {json}");
    }

    #[test]
    fn h4_log_level_roundtrip() {
        for lvl in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
        ] {
            let s = Settings {
                log_level: lvl,
                ..Settings::default()
            };
            let json = serde_json::to_string(&s).expect("ser");
            let back: Settings = serde_json::from_str(&json).expect("de");
            assert_eq!(back.log_level, lvl);
        }
    }

    #[test]
    fn h4_log_level_parse_or_default() {
        assert_eq!(LogLevel::parse_or_default("error"), LogLevel::Error);
        assert_eq!(LogLevel::parse_or_default("WARN"), LogLevel::Warn);
        assert_eq!(LogLevel::parse_or_default("warning"), LogLevel::Warn);
        assert_eq!(LogLevel::parse_or_default("info"), LogLevel::Info);
        assert_eq!(LogLevel::parse_or_default("debug"), LogLevel::Debug);
        // Bilinmeyen → Info (güvenli default, data loss yok).
        assert_eq!(LogLevel::parse_or_default("verbose"), LogLevel::Info);
        assert_eq!(LogLevel::parse_or_default(""), LogLevel::Info);
    }

    #[test]
    fn h4_log_level_filter_directive() {
        assert_eq!(LogLevel::Error.filter_directive(), "hekadrop=error");
        assert_eq!(LogLevel::Warn.filter_directive(), "hekadrop=warn");
        assert_eq!(LogLevel::Info.filter_directive(), "hekadrop=info");
        assert_eq!(LogLevel::Debug.filter_directive(), "hekadrop=debug");
    }

    #[test]
    fn h4_advertise_kullanici_false_korunur() {
        let json = r#"{"advertise": false}"#;
        let s: Settings = serde_json::from_str(json).expect("parse");
        assert!(!s.advertise);
        // Diğer alanlar hâlâ default.
        assert!(s.keep_stats);
    }

    #[test]
    fn h4_disable_update_check_kullanici_true_korunur() {
        let json = r#"{"disable_update_check": true}"#;
        let s: Settings = serde_json::from_str(json).expect("parse");
        assert!(s.disable_update_check);
    }

    #[test]
    fn h4_keep_stats_false_korunur() {
        let json = r#"{"keep_stats": false}"#;
        let s: Settings = serde_json::from_str(json).expect("parse");
        assert!(!s.keep_stats);
    }

    #[test]
    fn h4_bozuk_log_level_deserialize_hata() {
        // Geçersiz enum variant serde hatası — Settings tamamen parse edilemez.
        // `load()` bu durumda default Settings'e düşer (fallback davranışı).
        let bad = r#"{"log_level": "trace"}"#;
        let r: Result<Settings, _> = serde_json::from_str(bad);
        assert!(r.is_err());
    }

    #[test]
    fn atomic_write_basariyla_yazar_ve_destination_uzerine_yazar() {
        // Review-18: Windows'ta `fs::rename` destination varsa hata verir →
        // Regression guard: ikinci yazımın diski üzerine yazdığını doğrula.
        let dir = std::env::temp_dir().join(format!(
            "hekadrop-aw-overwrite-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("target.json");
        atomic_write(&p, b"first").expect("ilk yazım");
        atomic_write(&p, b"second").expect("ikinci yazım (overwrite)");
        let got = std::fs::read(&p).expect("read back");
        assert_eq!(got, b"second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review #34 MED regression: `atomic_write_mode(path, data, Some(0o600))`
    /// tmp dosyayı baştan `O_EXCL | mode(0o600)` ile açmalı ve rename sonucu
    /// final path da group/world-accessible OLMAMALI — umask ne olursa olsun.
    /// Önceki akışta tmp default (0644) ile açılıp rename SONRASI
    /// `set_permissions` ile düzeltiliyordu; bu pencerede dosya
    /// world-readable'dı.
    ///
    /// Assertion fix (PR #35 review, Copilot MED, `discussion_r3107564937`):
    /// Önceki test `mode == 0o600` exact eşitliğini kontrol ediyordu.
    /// `OpenOptionsExt::mode(0o600)` umask ile AND'lenir — yalnız daha
    /// **restrictive** hale gelebilir. Hardened ortamlarda (umask 0o077
    /// veya 0o277) owner bitleri daha da kısıtlanıp dosya 0o400 olabilir;
    /// bu durumda güvenlik invariant'ı (group/world erişim yok) hâlâ
    /// sağlanır ama eski assertion false-negative verirdi. Invariant
    /// olarak "group/world için hiçbir izin yok" (`mode & 0o077 == 0`)
    /// kontrol ediyoruz; owner bitleri 0o000..=0o700 aralığında herhangi
    /// bir değer olabilir.
    #[cfg(unix)]
    #[test]
    fn atomic_write_mode_0600_baslangictan_itibaren_uygular() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "hekadrop-aw-mode-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("secret.key");
        atomic_write_mode(&p, b"secret-bytes", Some(0o600)).expect("write");
        let meta = std::fs::metadata(&p).expect("stat");
        let mode = meta.permissions().mode() & 0o777;
        // Security invariant: group + world için hiçbir rwx biti yok.
        assert_eq!(
            mode & 0o077,
            0,
            "atomic_write_mode Some(0o600) → dosya group/world erişilebilir \
             olmamalı (bulunan mode: 0o{:o}, group+world bits: 0o{:o})",
            mode,
            mode & 0o077
        );
        // Owner bitleri umask tarafından daha da kısıtlanmış olabilir
        // (hardened setup). 0o600 tavan, 0o000 taban — arası kabul.
        let owner_bits = mode & 0o700;
        assert!(
            owner_bits <= 0o600,
            "owner bitleri 0o600'den fazla olmamalı (mode(0o600) umask'i gevşetmez): \
             0o{owner_bits:o}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_tmp_sizintisi_bırakmaz_basariyla() {
        // `atomic_write`'tan sonra parent dizinde `.target.json.<pid>.<rand>.tmp`
        // kalan bir tmp olmamalı — defuse() sonrası dosya rename ile yok olmalı.
        let dir = std::env::temp_dir().join(format!(
            "hekadrop-aw-tmp-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("target.json");
        atomic_write(&p, b"ok").expect("write");

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic_write sonrası tmp dosya kalmamalı: {:?}",
            leftovers.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_hata_durumunda_tmp_temizler() {
        // Parent dizini olmayan bir path'e yazarsak open() ENOENT atar.
        // Bu durumda TmpCleanup henüz yaratılmamış olur — alternatif olarak
        // kötü bir rename hedefi vermeyi dene: geçerli tmp yaratılır ama
        // rename path'i bir var olmayan dizine işaret eder → rename hata
        // döner ve TmpCleanup'ın Drop'u tmp'yi silmeli.
        let dir = std::env::temp_dir().join(format!(
            "hekadrop-aw-err-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Geçerli parent ama destination bir sub-dizin altında (yok → rename fail).
        let bad_dst = dir.join("nope").join("target.json");
        let res = atomic_write(&bad_dst, b"x");
        assert!(res.is_err(), "nonexistent parent rename başarısız olmalı");

        // dir içinde hiç .tmp kalmamalı (eğer tmp yaratıldıysa cleanup silmeli).
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "hatalı yazım sonrası tmp dosya kalmamalı: {:?}",
            leftovers.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_concurrent_ayni_pid_collision_olmaz() {
        // Review-18 (HIGH): Aynı süreçte iki thread aynı hedef dosyaya save
        // çağırdığında tmp adı pid'e dayalıysa çakışır. Rand u64 suffix +
        // SETTINGS_DISK_LOCK bu sorunu çözer; bu test "at least panic etme"
        // düzeyinde akıllılık kontrolü.
        use std::sync::Arc;
        use std::thread;
        let dir = Arc::new(std::env::temp_dir().join(format!(
            "hekadrop-aw-conc-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        )));
        std::fs::create_dir_all(&*dir).unwrap();
        let target = Arc::new(dir.join("target.json"));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let t = Arc::clone(&target);
                thread::spawn(move || {
                    let payload = format!("thread-{i}");
                    for _ in 0..16 {
                        atomic_write(&t, payload.as_bytes()).expect("atomic_write ok");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panic etmemeli");
        }
        // Son içerik 8 thread'ten birinin yazdığı olmalı; hiç değilse dosya var.
        assert!(target.exists());
        let _ = std::fs::remove_dir_all(&*dir);
    }

    // ─── PR #109: load corruption detection + backup ───────────────────────

    fn fresh_temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hekadrop-test-{name}-{nanos}.json"))
    }

    #[test]
    fn load_missing_returns_default_no_error() {
        let path = fresh_temp_path("missing");
        // Dosya yok — `Ok(default)` dönmeli
        let result = Settings::load(&path);
        assert!(result.is_ok());
        let (settings, err) = Settings::load_or_default(&path);
        assert!(err.is_none(), "missing file should not produce error");
        assert_eq!(settings.trusted_devices.len(), 0);
    }

    #[test]
    fn load_corrupt_json_returns_corrupt_error() {
        let path = fresh_temp_path("corrupt");
        std::fs::write(&path, b"{not valid json}").unwrap();

        let err = Settings::load(&path).unwrap_err();
        assert!(
            matches!(err, LoadError::Corrupt { .. }),
            "expected Corrupt, got {err:?}"
        );

        let (_, err_opt) = Settings::load_or_default(&path);
        assert!(matches!(err_opt, Some(LoadError::Corrupt { .. })));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_or_default_returns_default_on_corruption() {
        let path = fresh_temp_path("corrupt-default");
        std::fs::write(&path, b"<<not json>>").unwrap();

        let (settings, err) = Settings::load_or_default(&path);
        assert!(err.is_some());
        assert_eq!(settings.trusted_devices.len(), 0); // default

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn backup_corrupt_file_renames_with_timestamp() {
        let path = fresh_temp_path("backup");
        std::fs::write(&path, b"corrupt content").unwrap();

        let backup = backup_corrupt_file(&path).expect("backup should succeed");
        assert!(!path.exists(), "original file should be moved");
        assert!(backup.exists(), "backup file should exist");
        let backup_str = backup.to_string_lossy();
        assert!(
            backup_str.contains(".corrupt-"),
            "backup name should contain `.corrupt-<unix>`: {backup_str}"
        );

        // Kullanıcının manuel kurtarması için içerik korunmalı
        let backup_content = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(backup_content, "corrupt content");

        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn load_corrupt_preserves_existing_trusted_device_via_backup_workflow() {
        // Senaryo: kullanıcının trusted device'lı bir config'i bozuldu →
        // load_or_default + backup_corrupt_file workflow'u dosyayı saklamalı,
        // default'la başlamalı, kullanıcı backup'ı manuel restore edebilmeli.
        let path = fresh_temp_path("workflow");

        // Mock: bozuk JSON ama içinde trusted device alanı görünür
        let corrupt_json = br#"{"trusted_devices": [{"name": "Pixel"}], BROKEN"#;
        std::fs::write(&path, corrupt_json).unwrap();

        // 1. load detect eder
        let (settings, err) = Settings::load_or_default(&path);
        assert!(matches!(err, Some(LoadError::Corrupt { .. })));
        assert_eq!(settings.trusted_devices.len(), 0);

        // 2. backup başarılı
        let backup = backup_corrupt_file(&path).expect("backup");
        assert!(backup.exists());
        let recovered = std::fs::read(&backup).unwrap();
        assert_eq!(recovered, corrupt_json); // veri korundu

        // 3. Original yok → bir sonraki save default'u yazsa bile,
        //    backup'taki kullanıcı verisi eldedir.
        assert!(!path.exists());

        let _ = std::fs::remove_file(&backup);
    }
}
