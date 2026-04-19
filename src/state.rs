//! Global uygulama state'i — settings, aktif transfer progress'i ve son aktarım geçmişi.
//!
//! `OnceLock` ile tek seferlik init, `parking_lot::RwLock` ile lock-free-ish okuma.
//! Connection handler'ları progress ve history'yi günceller, tray thread'i okur.

use crate::identity::DeviceIdentity;
use crate::settings::Settings;
use crate::stats::Stats;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tokio_util::sync::CancellationToken;

const HISTORY_CAP: usize = 10;

/// Completed state'ini otomatik olarak Idle'a döndürmek için varsayılan gecikme.
pub const DEFAULT_COMPLETED_IDLE_DELAY: Duration = Duration::from_secs(3);

/// Anlık UI ilerleme durumu.
///
/// - [`Idle`](ProgressState::Idle): hiçbir transfer yok, progress bar gizli/boş.
/// - [`Receiving`](ProgressState::Receiving): aktarım sürüyor, yüzde [0, 100].
/// - [`Completed`](ProgressState::Completed): aktarım bitti; [`set_progress_completed_auto_idle`]
///   çağrıldıysa birkaç saniye sonra otomatik `Idle`'a döner.
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

pub struct AppState {
    pub settings: RwLock<Settings>,
    /// Cihaz-kalıcı kriptografik kimlik — `identity.key`'den yüklenir ya da
    /// ilk çalıştırmada üretilir. `PairedKeyEncryption.secret_id_hash` için
    /// kullanılır (Issue #17). Process boyunca immutable; `&DeviceIdentity`
    /// olarak paylaşılır.
    pub identity: DeviceIdentity,
    pub progress: RwLock<ProgressState>,
    /// Her progress mutasyonunda artan jeneratör. Gecikmeli reset görevleri bu sayıyı
    /// kendileri önce okur, zamanlayıcı dolduğunda aynı değeri görürlerse reset ederler —
    /// yani aradan başka bir aktarım geçmişse (yeni Receiving vb.) reset iptal olur.
    pub progress_gen: AtomicU64,
    pub history: RwLock<VecDeque<HistoryItem>>,
    pub listen_port: RwLock<u16>,
    /// Broadcast iptal kökü — `request_cancel_all()` bu token'ı cancel eder ve
    /// ondan türeyen tüm child token'lar (her per-transfer handler) tetiklenir.
    /// Cancel'den sonra yeni child'lar için `clear_cancel()` taze bir root üretir.
    pub cancel_root: RwLock<CancellationToken>,
    /// Aktif transferlerin id → token eşleşmesi. UI'dan spesifik bir transfer
    /// iptal edilmek istendiğinde (gelecekteki feature) bu haritadan bulunur.
    /// Her handler başlarken kendini kaydeder, biterken kaldırır.
    pub active_transfers: Mutex<HashMap<String, CancellationToken>>,
    /// IPC thread'inden pencereyi gizlemek için event loop'a istek.
    pub hide_window_flag: AtomicBool,
    /// IPC thread'inden pencereyi göstermek için event loop'a istek.
    pub show_window_flag: AtomicBool,
    /// IPC thread'inden UI'ya mesaj göndermek için kuyruk.
    /// Her eleman yürütülecek bir JS ifadesi.
    pub pending_js: RwLock<Vec<String>>,
    /// Gelen bağlantıların IP bazında rate limit takibi.
    pub rate_limiter: RateLimiter,
    /// Kalıcı kullanım istatistikleri.
    pub stats: RwLock<Stats>,
}

/// Sliding-window IP-bazlı rate limiter.
///
/// Trusted cihazlar bu limit'ten MUAFTIR (memory kuralı). Üst seviye çağrı önce
/// `Settings::is_trusted()` kontrol eder; trusted ise `check_and_record` hiç çağrılmaz.
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
}

static STATE: OnceLock<Arc<AppState>> = OnceLock::new();

pub fn init(settings: Settings) {
    // Issue #17: cihaz-kalıcı kimlik — bozuk / yazılamıyor senaryosunda
    // paniğe düşüp kullanıcıyı ikaz et; trust kararını güvenli şekilde
    // veremeyeceğimiz bir state ile devam etmeyelim.
    let identity = DeviceIdentity::load_or_create()
        .expect("DeviceIdentity yüklenemedi/oluşturulamadı — identity.key kontrol edin");
    let _ = STATE.set(Arc::new(AppState {
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
        stats: RwLock::new(Stats::load()),
    }));
}

/// Event loop, her tick'te bu kuyruktaki JS ifadelerini çalıştırır.
pub fn enqueue_js(js: String) {
    get().pending_js.write().push(js);
}

pub fn drain_js() -> Vec<String> {
    let st = get();
    let mut q = st.pending_js.write();
    std::mem::take(&mut *q)
}

pub fn request_hide_window() {
    get().hide_window_flag.store(true, Ordering::SeqCst);
}

pub fn request_show_window() {
    get().show_window_flag.store(true, Ordering::SeqCst);
}

/// Event loop ile koordinasyon: bayrak set ise true döner ve sıfırlar.
pub fn consume_hide_window() -> bool {
    get().hide_window_flag.swap(false, Ordering::SeqCst)
}

pub fn consume_show_window() -> bool {
    get().show_window_flag.swap(false, Ordering::SeqCst)
}

/// Yeni bir inbound/outbound transfer handler'ı çağırmadan önce bu fonksiyonu
/// kullanarak root'tan türeyen bir child token alır. Broadcast cancel
/// (`request_cancel_all`) hem root'u hem tüm child'ları tetikler.
pub fn new_child_token() -> CancellationToken {
    get().cancel_root.read().child_token()
}

/// Transferi id ile kaydeder. Aynı id daha önce kayıtlıysa üzerine yazılır —
/// bu senaryo pratikte olmamalı (her handler unique id üretir), ama idempotent
/// davranış test edilebilirlik için tercih edildi.
pub fn register_transfer(id: impl Into<String>, token: CancellationToken) {
    get().active_transfers.lock().insert(id.into(), token);
}

pub fn unregister_transfer(id: &str) {
    get().active_transfers.lock().remove(id);
}

/// RAII: scope sonunda `unregister_transfer` çağırır. Early-return / `?`
/// yollarında da temizlik garantili.
pub struct TransferGuard {
    id: String,
    pub token: CancellationToken,
}

impl TransferGuard {
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        let token = new_child_token();
        register_transfer(id.clone(), token.clone());
        Self { id, token }
    }
}

impl Drop for TransferGuard {
    fn drop(&mut self) {
        unregister_transfer(&self.id);
    }
}

/// UI'dan iptal isteği. `id == None` → root cancel (tüm aktif transferler).
/// `id == Some(...)` → yalnız o transfer'e ait child token cancel; diğerleri
/// etkilenmez. Bilinmeyen id sessizce yutulur (race: transfer bitmiş olabilir).
pub fn request_cancel(id: Option<&str>) {
    let st = get();
    match id {
        None => {
            st.cancel_root.read().cancel();
        }
        Some(id) => {
            if let Some(tok) = st.active_transfers.lock().get(id).cloned() {
                tok.cancel();
            }
        }
    }
}

/// Legacy kompat: tray menüsündeki "İptal" "hepsini iptal et" anlamındaydı.
pub fn request_cancel_all() {
    request_cancel(None);
}

/// Root token cancel'lenmişse taze bir root üretir. Cancel edilmemişse no-op.
///
/// Bir kez cancel edildikten sonra `CancellationToken` kalıcıdır — tekrar
/// kullanılamaz. `cleanup_transfer_state()` buradan BİLEREK kaçınır: in-flight
/// diğer transferlerin tokenı canlı kalmalı. Yalnızca tüm broadcast cancel
/// tamamlandıktan sonra (örn. kullanıcı yeni bir gönderim başlattığında) yeni
/// root'a geçmek güvenlidir.
pub fn clear_cancel() {
    let st = get();
    let mut guard = st.cancel_root.write();
    if guard.is_cancelled() {
        *guard = CancellationToken::new();
    }
}

pub fn set_listen_port(p: u16) {
    *get().listen_port.write() = p;
}

pub fn listen_port() -> u16 {
    *get().listen_port.read()
}

pub fn push_history(item: HistoryItem) {
    let st = get();
    let mut h = st.history.write();
    h.push_front(item);
    while h.len() > HISTORY_CAP {
        h.pop_back();
    }
}

pub fn read_history() -> Vec<HistoryItem> {
    get().history.read().iter().cloned().collect()
}

pub fn get() -> Arc<AppState> {
    STATE
        .get()
        .expect("state::init() çağrılmadan state::get() çağrıldı")
        .clone()
}

/// Progress'i atomik olarak günceller, jenerasyonu artırır ve yeni jenerasyon
/// değerini döndürür.
///
/// Write lock altında hem progress'i yazar hem gen'i arttırır — bu ikisinin
/// arasında başka bir `set_progress` çağrısı olamaz. Dolayısıyla döndürülen
/// değer, çağıranın `set` ettiği progress durumuna birebir karşılık gelir ve
/// gecikmeli görevler bu değeri yarış koşulu riski olmadan yakalayabilir.
fn set_progress_returning_gen(p: ProgressState) -> u64 {
    let st = get();
    let mut guard = st.progress.write();
    *guard = p;
    // Write lock zaten release/acquire sync sağlar; AcqRel defansif tercih.
    st.progress_gen.fetch_add(1, Ordering::AcqRel) + 1
}

/// Progress'i günceller ve değişiklik jenerasyonunu artırır.
pub fn set_progress(p: ProgressState) {
    let _ = set_progress_returning_gen(p);
}

pub fn read_progress() -> ProgressState {
    get().progress.read().clone()
}

/// Mevcut progress jenerasyonunu döner. Gecikmeli reset görevleri bu değeri
/// kendileri önce okuyup, zamanlayıcı dolduğunda aynı değerin hâlâ geçerli
/// olup olmadığını kontrol ederler.
pub fn progress_generation() -> u64 {
    get().progress_gen.load(Ordering::Acquire)
}

/// `Completed { file }` durumunu yazar ve `delay` süresi sonunda — eğer o
/// arada başka bir progress mutasyonu olmadıysa — otomatik olarak `Idle`'a
/// döner.
///
/// Yakalanan jenerasyon, Completed'i yazan *aynı* write lock altında üretilir
/// (bkz. `set_progress_returning_gen`); bu yüzden "yaz" ile "gen'i yakala"
/// arasında başka bir thread araya giremez.
///
/// Bu fonksiyon Tokio runtime context'i içinde çağrılmalıdır.
pub fn set_progress_completed_auto_idle(file: String, delay: Duration) {
    let captured_gen = set_progress_returning_gen(ProgressState::Completed { file });
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        // Sleep sırasında başka bir mutasyon olmadıysa Idle'a dön.
        if progress_generation() == captured_gen {
            set_progress(ProgressState::Idle);
        }
    });
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
