//! App-side singleton plumbing — `AppState` plain struct'ı core'da
//! (`hekadrop_core::state`); burada process-level singleton (`OnceLock`),
//! `init`/`get` ve geriye-uyumlu free-fn shim'ler yer alır.
//!
//! RFC-0001 §5 Adım 5c — struct + impl + `TransferGuard` + `ProgressState` +
//! `RateLimiter` + `HistoryItem` core'a taşındı; `pub use`
//! re-export'ları ile in-tree call site'lar (90+ yer: `state::ProgressState`,
//! `state::TransferGuard::new`, `state::HistoryItem`, vs.) dokunulmadan
//! derlenir.
//!
//! Singleton plumbing app-only kalır (CLAUDE.md I-6: core'da hidden global
//! state YASAK).

// API: app yüzeyini koru — `hekadrop::state::*` consumer'ları (lib.rs
// re-export) `TransferGuard`, `RateLimiter`, `DEFAULT_COMPLETED_IDLE_DELAY`
// sembollerini bekliyor. `cargo machete` style "kullanmayan ihaneti" yerine
// kasıtlı API genişliği — bin'de doğrudan referans yok ama integration
// test'leri ve gelecekteki UI tab'ları için açık tutuluyor.
#[allow(unused_imports)]
pub use hekadrop_core::state::{
    AppState, HistoryItem, ProgressState, RateLimiter, TransferGuard, DEFAULT_COMPLETED_IDLE_DELAY,
};

use hekadrop_core::settings::Settings;
use std::sync::{Arc, OnceLock};

static STATE: OnceLock<Arc<AppState>> = OnceLock::new();

pub fn init(settings: Settings) {
    // App-singleton katmanı path'leri ve platform default'larını inject
    // ediyor — `AppState::new` core'da global'siz çalışır. Path resolution
    // `crate::paths` (`crate::platform::config_dir()` üstünde) sorumluluğu;
    // default device adı ve indirme dizini `crate::platform`'dan tek seferlik
    // resolve.
    let _ = STATE.set(AppState::new(
        settings,
        &crate::paths::identity_path(),
        crate::paths::config_path(),
        crate::paths::stats_path(),
        crate::platform::device_name(),
        crate::platform::default_download_dir(),
    ));
}

pub fn get() -> Arc<AppState> {
    // INVARIANT: `init()` her zaman `main`'in ilk işlerinden — `get()`
    // öncesinde çağrılması garanti. Aksi durum programlama hatası, panik
    // yerine sessiz default state üretmek bug'ı maskeler.
    #[allow(clippy::expect_used)]
    STATE
        .get()
        .expect("state::init() çağrılmadan state::get() çağrıldı")
        .clone()
}

// ── Free-fn shim'ler — caller API'sini koruyoruz (90 callsite) ─────────────
//
// Yalnız main.rs'in kullandığı sembolleri tutuyoruz; sender/connection/server
// (artık core'da) doğrudan `Arc<AppState>` parametresi alıyor — singleton
// lookup yok.

pub fn enqueue_js(js: String) {
    get().enqueue_js(js);
}

pub fn drain_js() -> Vec<String> {
    get().drain_js()
}

pub fn request_hide_window() {
    get().request_hide_window();
}

pub fn request_show_window() {
    get().request_show_window();
}

pub fn consume_hide_window() -> bool {
    get().consume_hide_window()
}

pub fn consume_show_window() -> bool {
    get().consume_show_window()
}

pub fn request_cancel(id: Option<&str>) {
    get().request_cancel(id);
}

/// Legacy kompat: tray menüsündeki "İptal" "hepsini iptal et" anlamındaydı.
pub fn request_cancel_all() {
    request_cancel(None);
}

pub fn set_listen_port(p: u16) {
    get().set_listen_port(p);
}

pub fn listen_port() -> u16 {
    get().listen_port()
}

pub fn read_history() -> Vec<HistoryItem> {
    get().read_history()
}

pub fn read_progress() -> ProgressState {
    get().read_progress()
}
