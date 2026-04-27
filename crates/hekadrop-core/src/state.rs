//! Plain `AppState` struct + impl — Adım 5c (RFC-0001 §5) ile core'a taşındı.
//!
//! Bu modülde **process-level singleton YOK** (CLAUDE.md I-6). `Arc<AppState>`
//! caller tarafından inject edilir; app-side singleton plumbing
//! (`OnceLock<Arc<AppState>>` + `init`/`get` + free-fn shim'ler) ayrı bir
//! katmanda — `crates/hekadrop-app/src/state.rs` — yer alır.
//!
//! Public surface:
//! - `AppState` (RwLock'lu state container)
//! - `ProgressState`, `HistoryItem` (POD enum/struct)
//! - `RateLimiter` (sliding-window IP-bazlı limiter, AppState alanı)
//! - `TransferGuard` (RAII; `Arc<AppState>` tutar, Drop'ta unregister)
//! - `DEFAULT_COMPLETED_IDLE_DELAY` (Completed → Idle gecikme sabiti)

use crate::identity::DeviceIdentity;
use crate::settings::Settings;
use crate::stats::Stats;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio_util::sync::CancellationToken;

const HISTORY_CAP: usize = 10;

/// Completed state'ini otomatik olarak Idle'a döndürmek için varsayılan gecikme.
pub const DEFAULT_COMPLETED_IDLE_DELAY: Duration = Duration::from_secs(3);

/// Anlık UI ilerleme durumu.
///
/// - [`Idle`](ProgressState::Idle): hiçbir transfer yok, progress bar gizli/boş.
/// - [`Receiving`](ProgressState::Receiving): aktarım sürüyor, yüzde [0, 100].
/// - [`Completed`](ProgressState::Completed): aktarım bitti;
///   `AppState::set_progress_completed_auto_idle` çağrıldıysa birkaç saniye
///   sonra otomatik `Idle`'a döner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgressState {
    Idle,
    Receiving {
        device: String,
        file: String,
        percent: u8,
    },
    Completed {
        file: String,
    },
}

#[derive(Clone, Debug)]
pub struct HistoryItem {
    pub file_name: String,
    #[allow(dead_code)]
    pub path: PathBuf,
    pub size: i64,
    pub device: String,
    pub when: SystemTime,
    /// İlk 16 hex karakter (kısaltılmış SHA-256) — UI'da gösterilir.
    pub sha256_short: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// AppState — plain struct (process-level singleton YOK; bkz. modül başlığı)
// ─────────────────────────────────────────────────────────────────────────────

pub struct AppState {
    pub settings: RwLock<Settings>,
    /// Cihaz-kalıcı kriptografik kimlik — `identity.key`'den yüklenir ya da
    /// ilk çalıştırmada üretilir. `PairedKeyEncryption.secret_id_hash` için
    /// kullanılır (Issue #17). Process boyunca immutable; `&DeviceIdentity`
    /// olarak paylaşılır.
    pub identity: DeviceIdentity,
    pub progress: RwLock<ProgressState>,
    /// Her progress mutasyonunda artan jeneratör. Gecikmeli reset görevleri
    /// bu sayıyı kendileri önce okur, zamanlayıcı dolduğunda aynı değeri
    /// görürlerse reset ederler — yani aradan başka bir aktarım geçmişse
    /// (yeni Receiving vb.) reset iptal olur.
    pub progress_gen: AtomicU64,
    pub history: RwLock<VecDeque<HistoryItem>>,
    pub listen_port: RwLock<u16>,
    /// Broadcast iptal kökü — `request_cancel(None)` bu token'ı cancel eder
    /// ve ondan türeyen tüm child token'lar (her per-transfer handler)
    /// tetiklenir. Cancel'den sonra yeni child'lar için `clear_cancel()`
    /// taze bir root üretir.
    pub cancel_root: RwLock<CancellationToken>,
    /// Aktif transferlerin id → token eşleşmesi. UI'dan spesifik bir
    /// transfer iptal edilmek istendiğinde bu haritadan bulunur. Her
    /// handler başlarken kendini kaydeder, biterken kaldırır.
    pub active_transfers: Mutex<HashMap<String, CancellationToken>>,
    /// IPC thread'inden pencereyi gizlemek için event loop'a istek.
    pub hide_window_flag: AtomicBool,
    /// IPC thread'inden pencereyi göstermek için event loop'a istek.
    pub show_window_flag: AtomicBool,
    /// IPC thread'inden UI'ya mesaj göndermek için kuyruk. Her eleman
    /// yürütülecek bir JS ifadesi.
    pub pending_js: RwLock<Vec<String>>,
    /// Gelen bağlantıların IP bazında rate limit takibi.
    pub rate_limiter: RateLimiter,
    /// Kalıcı kullanım istatistikleri.
    pub stats: RwLock<Stats>,
    /// Settings persistence yolu — app crate'inde resolve edilir, AppState
    /// burada cache'ler. Connection trusted-list update'leri bu yolu
    /// doğrudan kullanır (paths app-only).
    pub config_path: PathBuf,
    /// Stats persistence yolu — app crate'inde resolve edilir, AppState
    /// burada cache'ler. Sender ve connection RX path bu yolu doğrudan
    /// kullanır (paths app-only).
    pub stats_path: PathBuf,
    /// Platform-default device adı — kullanıcı `Settings.device_name`
    /// override'ı yoksa fallback. App startup'ta tek seferlik resolve.
    /// Sender / receive path
    /// `Settings::resolved_device_name(|| state.default_device_name.clone())`
    /// closure'u ile alır.
    pub default_device_name: String,
    /// Platform-default indirme dizini — `Settings.download_dir` yoksa
    /// fallback. App startup'ta tek seferlik resolve edilir.
    pub default_download_dir: PathBuf,
}

impl AppState {
    /// Yeni bir `AppState` kurar ve `Arc` içine sarar.
    ///
    /// Bu konstrüktör global state'e DOKUNMAZ — `identity_path`,
    /// `config_path`, `stats_path` ve platform default'ları caller
    /// (app-singleton katmanı) tarafından inject edilir. Bu sayede
    /// `AppState` core'da `crate::paths` veya `crate::platform` (app-only)
    /// bağımlılığı sızdırmaz.
    pub fn new(
        settings: Settings,
        identity_path: &std::path::Path,
        config_path: PathBuf,
        stats_path: PathBuf,
        default_device_name: String,
        default_download_dir: PathBuf,
    ) -> Arc<Self> {
        // INVARIANT (security): trust kararı identity'ye dayanıyor — bozuk /
        // yazılamıyor identity ile yola devam etmek "her cihaz aynı görünür"
        // güvenlik açığı doğurur. Startup'ta panik = kullanıcıya hata göster,
        // devam etme. Issue #17.
        #[allow(clippy::expect_used)]
        let identity = DeviceIdentity::load_or_create_at(identity_path)
            .expect("DeviceIdentity yüklenemedi/oluşturulamadı — identity.key kontrol edin");
        let stats_loaded = Stats::load(&stats_path);
        Arc::new(Self {
            settings: RwLock::new(settings),
            identity,
            progress: RwLock::new(ProgressState::Idle),
            progress_gen: AtomicU64::new(0),
            history: RwLock::new(VecDeque::with_capacity(HISTORY_CAP)),
            listen_port: RwLock::new(0),
            cancel_root: RwLock::new(CancellationToken::new()),
            active_transfers: Mutex::new(HashMap::new()),
            hide_window_flag: AtomicBool::new(false),
            show_window_flag: AtomicBool::new(false),
            pending_js: RwLock::new(Vec::new()),
            rate_limiter: RateLimiter::new(),
            stats: RwLock::new(stats_loaded),
            config_path,
            stats_path,
            default_device_name,
            default_download_dir,
        })
    }

    // ── pending_js / window flags ───────────────────────────────────────────

    /// Event loop, her tick'te bu kuyruktaki JS ifadelerini çalıştırır.
    pub fn enqueue_js(&self, js: String) {
        self.pending_js.write().push(js);
    }

    pub fn drain_js(&self) -> Vec<String> {
        let mut q = self.pending_js.write();
        std::mem::take(&mut *q)
    }

    pub fn request_hide_window(&self) {
        self.hide_window_flag.store(true, Ordering::SeqCst);
    }

    pub fn request_show_window(&self) {
        self.show_window_flag.store(true, Ordering::SeqCst);
    }

    /// Event loop ile koordinasyon: bayrak set ise true döner ve sıfırlar.
    pub fn consume_hide_window(&self) -> bool {
        self.hide_window_flag.swap(false, Ordering::SeqCst)
    }

    pub fn consume_show_window(&self) -> bool {
        self.show_window_flag.swap(false, Ordering::SeqCst)
    }

    // ── cancel / transfer registry ──────────────────────────────────────────

    /// Yeni bir inbound/outbound transfer handler'ı çağırmadan önce bu
    /// fonksiyonu kullanarak root'tan türeyen bir child token alır. Broadcast
    /// cancel (`request_cancel(None)`) hem root'u hem tüm child'ları tetikler.
    pub fn new_child_token(&self) -> CancellationToken {
        self.cancel_root.read().child_token()
    }

    /// Transferi id ile kaydeder. Aynı id daha önce kayıtlıysa üzerine yazılır
    /// — bu senaryo pratikte olmamalı (her handler unique id üretir), ama
    /// idempotent davranış test edilebilirlik için tercih edildi.
    pub fn register_transfer(&self, id: impl Into<String>, token: CancellationToken) {
        self.active_transfers.lock().insert(id.into(), token);
    }

    pub fn unregister_transfer(&self, id: &str) {
        self.active_transfers.lock().remove(id);
    }

    /// UI'dan iptal isteği. `id == None` → root cancel (tüm aktif
    /// transferler). `id == Some(...)` → yalnız o transfer'e ait child token
    /// cancel; diğerleri etkilenmez. Bilinmeyen id sessizce yutulur (race:
    /// transfer bitmiş olabilir).
    pub fn request_cancel(&self, id: Option<&str>) {
        match id {
            None => {
                self.cancel_root.read().cancel();
            }
            Some(id) => {
                if let Some(tok) = self.active_transfers.lock().get(id).cloned() {
                    tok.cancel();
                }
            }
        }
    }

    /// Root token cancel'lenmişse taze bir root üretir. Cancel edilmemişse
    /// no-op.
    ///
    /// Bir kez cancel edildikten sonra `CancellationToken` kalıcıdır — tekrar
    /// kullanılamaz. `cleanup_transfer_state()` buradan BİLEREK kaçınır:
    /// in-flight diğer transferlerin tokenı canlı kalmalı. Yalnızca tüm
    /// broadcast cancel tamamlandıktan sonra (örn. kullanıcı yeni bir
    /// gönderim başlattığında) yeni root'a geçmek güvenlidir.
    pub fn clear_cancel(&self) {
        // Fast path: ortak durum (root temiz) yalnızca read-lock alır.
        // Yalnızca gerçekten cancelled ise write-lock'a upgrade ediyoruz —
        // her transfer başında gereksiz exclusive lock contention'ını engeller.
        if !self.cancel_root.read().is_cancelled() {
            return;
        }
        let mut guard = self.cancel_root.write();
        // Write-lock beklerken başka bir thread zaten yeni root yazmış
        // olabilir: tekrar kontrol et.
        if guard.is_cancelled() {
            *guard = CancellationToken::new();
        }
    }

    // ── listen port ─────────────────────────────────────────────────────────

    pub fn set_listen_port(&self, p: u16) {
        *self.listen_port.write() = p;
    }

    pub fn listen_port(&self) -> u16 {
        *self.listen_port.read()
    }

    // ── history ─────────────────────────────────────────────────────────────

    pub fn push_history(&self, item: HistoryItem) {
        let mut h = self.history.write();
        h.push_front(item);
        while h.len() > HISTORY_CAP {
            h.pop_back();
        }
    }

    pub fn read_history(&self) -> Vec<HistoryItem> {
        self.history.read().iter().cloned().collect()
    }

    // ── progress ────────────────────────────────────────────────────────────

    /// Progress'i atomik olarak günceller, jenerasyonu artırır ve yeni
    /// jenerasyon değerini döndürür.
    ///
    /// Write lock altında hem progress'i yazar hem gen'i arttırır — bu
    /// ikisinin arasında başka bir `set_progress` çağrısı olamaz. Dolayısıyla
    /// döndürülen değer, çağıranın `set` ettiği progress durumuna birebir
    /// karşılık gelir ve gecikmeli görevler bu değeri yarış koşulu riski
    /// olmadan yakalayabilir.
    pub fn set_progress(&self, p: ProgressState) -> u64 {
        let mut guard = self.progress.write();
        *guard = p;
        // Write lock zaten release/acquire sync sağlar; AcqRel defansif tercih.
        self.progress_gen.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn read_progress(&self) -> ProgressState {
        self.progress.read().clone()
    }

    /// Mevcut progress jenerasyonunu döner. Gecikmeli reset görevleri bu
    /// değeri kendileri önce okuyup, zamanlayıcı dolduğunda aynı değerin
    /// hâlâ geçerli olup olmadığını kontrol ederler.
    pub fn progress_generation(&self) -> u64 {
        self.progress_gen.load(Ordering::Acquire)
    }

    /// `Completed { file }` durumunu yazar ve `delay` süresi sonunda — eğer
    /// arada başka bir progress mutasyonu olmadıysa — otomatik olarak
    /// `Idle`'a döner.
    ///
    /// Yakalanan jenerasyon, Completed'i yazan *aynı* write lock altında
    /// üretilir; bu yüzden "yaz" ile "gen'i yakala" arasında başka bir thread
    /// araya giremez. Bu fonksiyon Tokio runtime context'i içinde
    /// çağrılmalıdır.
    ///
    /// `Weak` referans saklanır — sleep sırasında AppState drop edilirse
    /// (test teardown / process shutdown) reset task no-op'lar.
    ///
    /// `Handle::try_current()` ile mevcut Tokio runtime detect edilir; runtime
    /// dışı caller (CLI/test/FFI) için panik yerine reset task **skip** edilir
    /// — `Completed` durumu kalıcı olur, caller manuel `Idle`'a alabilir.
    /// PR #93 review (Copilot): core API non-tokio context'te de güvenli
    /// olmalı.
    pub fn set_progress_completed_auto_idle(self: &Arc<Self>, file: String, delay: Duration) {
        let captured_gen = self.set_progress(ProgressState::Completed { file });
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // Tokio runtime yok — auto-idle reset planlanamaz; Completed
            // durumu kalır.
            return;
        };
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            tokio::time::sleep(delay).await;
            let Some(s) = weak.upgrade() else { return };
            // Sleep sırasında başka bir mutasyon olmadıysa Idle'a dön.
            if s.progress_generation() == captured_gen {
                s.set_progress(ProgressState::Idle);
            }
        });
    }
}

/// RAII: scope sonunda `unregister_transfer` çağırır. Early-return / `?`
/// yollarında da temizlik garantili.
///
/// Adım 5c sonrası guard `Arc<AppState>` tutar; `Drop` global singleton
/// lookup'ı yapmadan kendi state referansı üzerinden temizler. Bu sayede
/// guard core crate'inde de kullanılabilir (no `state::get()`).
pub struct TransferGuard {
    state: Arc<AppState>,
    id: String,
    pub token: CancellationToken,
}

impl TransferGuard {
    /// Yeni bir transfer guard'ı kurar. Eğer önceki broadcast cancel sonrası
    /// root hâlâ cancelled durumdaysa önce `clear_cancel()` ile taze root'a
    /// geçer — aksi halde bu yeni transfer doğar doğmaz cancelled olur
    /// (footgun: eski tasarımda callsite'lar elle `clear_cancel()` çağırmak
    /// zorundaydı). RAII kapsülü olarak bu çağrıyı tek noktaya topluyoruz.
    pub fn new(state: Arc<AppState>, id: impl Into<String>) -> Self {
        let id = id.into();
        state.clear_cancel();
        let token = state.new_child_token();
        state.register_transfer(id.clone(), token.clone());
        Self { state, id, token }
    }
}

impl Drop for TransferGuard {
    fn drop(&mut self) {
        self.state.unregister_transfer(&self.id);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RateLimiter — plain helper (AppState alanı)
// ─────────────────────────────────────────────────────────────────────────────

/// Sliding-window IP-bazlı rate limiter.
///
/// Trusted cihazlar bu limit'ten MUAFTIR (memory kuralı). Üst seviye çağrı önce
/// `Settings::is_trusted()` kontrol eder; trusted ise `check_and_record` hiç
/// çağrılmaz.
pub struct RateLimiter {
    windows: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_PER_WINDOW: usize = 10;

    pub fn new() -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
        }
    }

    /// Son 60 saniyede bu IP'den 10+ bağlantı varsa true döner (limit aşıldı).
    /// Aksi halde false döner ve bu bağlantıyı timestamp olarak kaydeder.
    pub fn check_and_record(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.write();
        let q = windows.entry(ip).or_default();

        while let Some(&front) = q.front() {
            if now.duration_since(front) > Self::WINDOW {
                q.pop_front();
            } else {
                break;
            }
        }

        if q.len() >= Self::MAX_PER_WINDOW {
            return true;
        }
        q.push_back(now);
        false
    }

    /// Bu IP için kaydedilmiş son timestamp'i siler. Trusted hash
    /// doğrulandıktan sonra geriye-dönük muafiyet uygulamak için kullanılır
    /// (gate'de hash yoktu, PairedKey sonrası kanıt geldi → sayacı düzelt).
    /// Issue #17.
    pub fn forget_most_recent(&self, ip: IpAddr) {
        let mut windows = self.windows.write();
        if let Some(q) = windows.get_mut(&ip) {
            q.pop_back();
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rate_limiter_accepts_until_cap_then_blocks() {
        let rl = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..RateLimiter::MAX_PER_WINDOW {
            assert!(!rl.check_and_record(ip));
        }
        // 11. istek limit aşıldığı için true döner.
        assert!(rl.check_and_record(ip));
    }

    #[test]
    fn rate_limiter_isolates_per_ip() {
        let rl = RateLimiter::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..RateLimiter::MAX_PER_WINDOW {
            assert!(!rl.check_and_record(a));
        }
        // b henüz hiç istek atmadı — limit'ten etkilenmez.
        assert!(!rl.check_and_record(b));
        // a ise dolmuş.
        assert!(rl.check_and_record(a));
    }

    #[test]
    fn progress_state_equality() {
        assert_eq!(ProgressState::Idle, ProgressState::Idle);
        assert_ne!(
            ProgressState::Idle,
            ProgressState::Completed { file: "x".into() }
        );
    }
}
