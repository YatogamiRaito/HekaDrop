//! Global uygulama state'i — settings, aktif transfer progress'i ve son aktarım geçmişi.
//!
//! `OnceLock` ile tek seferlik init, `parking_lot::RwLock` ile lock-free-ish okuma.
//! Connection handler'ları progress ve history'yi günceller, tray thread'i okur.

use crate::settings::Settings;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

const HISTORY_CAP: usize = 10;

#[derive(Clone, Debug)]
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
}

pub struct AppState {
    pub settings: RwLock<Settings>,
    pub progress: RwLock<ProgressState>,
    pub history: RwLock<VecDeque<HistoryItem>>,
    pub listen_port: RwLock<u16>,
    /// Aktif aktarımı iptal etmek için ayarlanır. Transfer loop'ları kontrol edip temiz kapanış yapar.
    pub cancel_flag: AtomicBool,
    /// IPC thread'inden pencereyi gizlemek için event loop'a istek.
    pub hide_window_flag: AtomicBool,
    /// IPC thread'inden pencereyi göstermek için event loop'a istek.
    pub show_window_flag: AtomicBool,
}

static STATE: OnceLock<Arc<AppState>> = OnceLock::new();

pub fn init(settings: Settings) {
    let _ = STATE.set(Arc::new(AppState {
        settings: RwLock::new(settings),
        progress: RwLock::new(ProgressState::Idle),
        history: RwLock::new(VecDeque::with_capacity(HISTORY_CAP)),
        listen_port: RwLock::new(0),
        cancel_flag: AtomicBool::new(false),
        hide_window_flag: AtomicBool::new(false),
        show_window_flag: AtomicBool::new(false),
    }));
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

/// UI'dan aktif transferin iptali istenir. Transfer loop'u görür ve temiz kapanır.
pub fn request_cancel() {
    get().cancel_flag.store(true, Ordering::SeqCst);
}

/// Transfer loop'u iptal bayrağını okur; true dönerse kullanıcı iptal istemiş demektir.
pub fn is_cancelled() -> bool {
    get().cancel_flag.load(Ordering::SeqCst)
}

/// İptal bayrağını temizler — yeni bir transfer başladığında sıfırlanmalıdır.
pub fn clear_cancel() {
    get().cancel_flag.store(false, Ordering::SeqCst);
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

pub fn set_progress(p: ProgressState) {
    *get().progress.write() = p;
}

pub fn read_progress() -> ProgressState {
    get().progress.read().clone()
}
