//! Platformdan bağımsız yardımcılar — config/logs yolları, device adı,
//! dosya/URL açma, panoya kopyalama, otomatik başlatma.
//!
//! Bu modül tek giriş noktasıdır; çağıranlar (`settings`, `stats`, `main`,
//! `connection`, `ui`) platforma göre ayrım yapmaz. Yeni target'lar (Linux,
//! Windows) eklerken sadece burası genişletilir.
//!
//! Windows implementasyonu `windows-rs` binding'ini kullanır; external
//! process spawn (cmd/explorer/clip) yerine native Win32 API'lerine
//! doğrudan çağrı yapar — bu sayede UTF-16 doğruluğu, düşük gecikme ve
//! temiz hata yolları sağlanır.

use std::path::{Path, PathBuf};
#[cfg(not(target_os = "windows"))]
use std::process::Command;

/// Kullanıcı home dizini.
///
/// - macOS / Linux: `$HOME` (tanımsızsa `/tmp` fallback)
/// - Windows: `%USERPROFILE%` (tanımsızsa `C:\Users\Default` fallback)
#[cfg(not(target_os = "windows"))]
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[cfg(target_os = "windows")]
fn home_dir() -> PathBuf {
    win::known_folder(&windows::Win32::UI::Shell::FOLDERID_Profile)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default"))
}

/// Uygulamanın kalıcı ayar dizini.
///
/// - macOS: `~/Library/Application Support/HekaDrop`
/// - Linux: `$XDG_CONFIG_HOME/HekaDrop` → `~/.config/HekaDrop`
/// - Windows: `FOLDERID_RoamingAppData\HekaDrop` (genelde `%APPDATA%\HekaDrop`)
pub(crate) fn config_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Application Support/HekaDrop")
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop");
        }
        home_dir().join(".config/HekaDrop")
    }
    #[cfg(target_os = "windows")]
    {
        win::known_folder(&windows::Win32::UI::Shell::FOLDERID_RoamingAppData)
            .map(|p| p.join("HekaDrop"))
            .unwrap_or_else(|| home_dir().join(r"AppData\Roaming\HekaDrop"))
    }
}

/// Log dosyalarının gideceği dizin.
///
/// - macOS: `~/Library/Logs/HekaDrop`
/// - Linux: `$XDG_STATE_HOME/HekaDrop/logs` → `~/.local/state/HekaDrop/logs`
/// - Windows: `FOLDERID_LocalAppData\HekaDrop\logs` — log'lar roam etmesin.
pub(crate) fn logs_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Logs/HekaDrop")
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop/logs");
        }
        home_dir().join(".local/state/HekaDrop/logs")
    }
    #[cfg(target_os = "windows")]
    {
        win::known_folder(&windows::Win32::UI::Shell::FOLDERID_LocalAppData)
            .map(|p| p.join(r"HekaDrop\logs"))
            .unwrap_or_else(|| home_dir().join(r"AppData\Local\HekaDrop\logs"))
    }
}

/// Varsayılan indirme klasörü.
///
/// - Linux: `xdg-user-dir DOWNLOAD` → fallback `$HOME/Downloads`
/// - macOS: `$HOME/Downloads`
/// - Windows: `FOLDERID_Downloads` (kullanıcının özel konuma taşımış olması
///   durumunda da doğru yolu döner)
pub(crate) fn default_download_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("xdg-user-dir").arg("DOWNLOAD").output() {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return PathBuf::from(trimmed);
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(p) = win::known_folder(&windows::Win32::UI::Shell::FOLDERID_Downloads) {
            return p;
        }
    }
    home_dir().join("Downloads")
}

/// mDNS / UI için gösterilecek cihaz adı.
///
/// - macOS: `scutil --get ComputerName`
/// - Linux: `/etc/hostname` → `hostname` komutu → fallback "`HekaDrop` Linux"
/// - Windows: `GetComputerNameExW(ComputerNameDnsHostname)` → fallback
///   `%COMPUTERNAME%` → "`HekaDrop` PC"
pub(crate) fn device_name() -> String {
    if let Ok(v) = std::env::var("HEKADROP_NAME") {
        if !v.is_empty() {
            return v;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
        {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let t = s.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
        "HekaDrop Mac".to_string()
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            let t = h.trim();
            if !t.is_empty() {
                return format!("HekaDrop {t}");
            }
        }
        if let Ok(out) = Command::new("hostname").output() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let t = s.trim();
                if !t.is_empty() {
                    return format!("HekaDrop {t}");
                }
            }
        }
        "HekaDrop Linux".to_string()
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(name) = win::computer_name() {
            return format!("HekaDrop {name}");
        }
        if let Ok(v) = std::env::var("COMPUTERNAME") {
            let t = v.trim();
            if !t.is_empty() {
                return format!("HekaDrop {t}");
            }
        }
        "HekaDrop PC".to_string()
    }
}

/// Verilen dosyayı/dizini işletim sisteminin varsayılan programıyla açar.
pub(crate) fn open_path(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(path).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        win::shell_execute_open(path.as_os_str());
    }
}

/// Dosyayı dosya yöneticisinde (Finder / Nautilus / Explorer) seçili olarak gösterir.
pub(crate) fn reveal_path(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        // D-Bus FileManager1 çoğu Linux DE'de mevcut; başarısızsa parent dizini açarız.
        // RFC 3986: file:// URI'sinde boşluk / `#` / `?` / `%` / non-ASCII vb.
        // karakterler percent-encode edilmeli — aksi halde URI parse'ı bozulur
        // ve Nautilus dosyayı bulamaz.
        let uri = path_to_file_uri(path);
        let dbus = Command::new("dbus-send")
            .args([
                "--session",
                "--dest=org.freedesktop.FileManager1",
                "--type=method_call",
                "/org/freedesktop/FileManager1",
                "org.freedesktop.FileManager1.ShowItems",
                &format!("array:string:{uri}"),
                "string:",
            ])
            .status();
        if matches!(dbus, Ok(s) if s.success()) {
            return;
        }
        let parent = path.parent().unwrap_or(path);
        let _ = Command::new("xdg-open").arg(parent).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        // `SHOpenFolderAndSelectItems` native API — dosyayı içeren klasörü
        // açar ve dosyayı seçili hale getirir. Başarısızsa parent dizini
        // ShellExecute ile aç.
        if win::select_in_explorer(path).is_err() {
            let parent = path.parent().unwrap_or(path);
            win::shell_execute_open(parent.as_os_str());
        }
    }
}

/// Bir dosya yolunu `file://` URI'sine çevirir (RFC 3986 percent-encoding).
///
/// Kaçmadan bırakılanlar: unreserved karakterler (`A-Z a-z 0-9 - . _ ~`)
/// ve path ayırıcı `/`. Diğer her şey — boşluk, `#`, `?`, `%`, Türkçe karakter
/// vb. — `%XX` olarak kodlanır. Bayt seviyesinde çalışır; UTF-8 sequence'ları
/// doğru biçimde kodlanır.
#[cfg(target_os = "linux")]
fn path_to_file_uri(path: &Path) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut out = String::from("file://");
    for &b in bytes {
        let unreserved = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/'
        );
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn uri_basit_path_kodlamadan_gecer() {
        assert_eq!(
            path_to_file_uri(Path::new("/home/user/file.pdf")),
            "file:///home/user/file.pdf"
        );
    }

    #[test]
    fn uri_bosluklu_dosya_adi_percent_encode() {
        assert_eq!(
            path_to_file_uri(Path::new("/home/user/my file.pdf")),
            "file:///home/user/my%20file.pdf"
        );
    }

    #[test]
    fn uri_hash_ve_soru_isareti_encode() {
        // `#` fragment, `?` query ayırıcısı olarak yorumlanacağından kodlanmalı.
        assert_eq!(
            path_to_file_uri(Path::new("/tmp/a#b?c.txt")),
            "file:///tmp/a%23b%3Fc.txt"
        );
    }

    #[test]
    fn uri_yuzde_isareti_kendisi_de_encode() {
        assert_eq!(
            path_to_file_uri(Path::new("/tmp/%20raw.txt")),
            "file:///tmp/%2520raw.txt"
        );
    }

    #[test]
    fn uri_turkce_karakterler_utf8_bayt_encode() {
        // "şarkı" → UTF-8: 0xC5 0x9F 0x61 0x72 0x6B 0xC4 0xB1
        let uri = path_to_file_uri(Path::new("/müzik/şarkı.mp3"));
        assert_eq!(uri, "file:///m%C3%BCzik/%C5%9Fark%C4%B1.mp3");
    }
}

/// URL'i tarayıcıda açar.
pub(crate) fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        win::shell_execute_open(std::ffi::OsStr::new(url));
    }
}

/// Panodan UTF-8 metin okur. Metin yoksa veya okuma başarısızsa `None`.
///
/// - macOS: `pbpaste`
/// - Linux: Wayland (`wl-paste`) → X11 (`xclip` → `xsel`) sırayla
/// - Windows: `GetClipboardData(CF_UNICODETEXT)` — UTF-16 → UTF-8 lossy
pub(crate) fn paste_from_clipboard() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        win::clipboard_get().ok().flatten()
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Stdio;

        #[cfg(target_os = "macos")]
        let candidates: &[&[&str]] = &[&["pbpaste"]];
        #[cfg(target_os = "linux")]
        let candidates: &[&[&str]] = &[
            &["wl-paste", "--no-newline"],
            &["xclip", "-selection", "clipboard", "-o"],
            &["xsel", "--clipboard", "--output"],
        ];

        for args in candidates {
            let mut cmd = Command::new(args[0]);
            if args.len() > 1 {
                cmd.args(&args[1..]);
            }
            let out = cmd.stderr(Stdio::null()).output();
            if let Ok(o) = out {
                if o.status.success() {
                    if let Ok(s) = String::from_utf8(o.stdout) {
                        return Some(s);
                    }
                }
            }
        }
        None
    }
}

/// Metni sistem panosuna kopyalar.
///
/// - macOS: `pbcopy`
/// - Linux: Wayland (`wl-copy`) → X11 (`xclip` → `xsel`) sırayla
/// - Windows: `OpenClipboard` + `SetClipboardData(CF_UNICODETEXT)` — UTF-16 LE,
///   `clip.exe`'nin ANSI-yorumu yüzünden Türkçe/non-ASCII bozulmasın
pub(crate) fn copy_to_clipboard(text: &str) {
    #[cfg(target_os = "windows")]
    {
        if win::clipboard_set(text).is_err() {
            tracing::warn!("panoya kopyalama başarısız — Win32 SetClipboardData hata döndü");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::io::Write;
        use std::process::Stdio;

        #[cfg(target_os = "macos")]
        let candidates: &[&[&str]] = &[&["pbcopy"]];
        #[cfg(target_os = "linux")]
        let candidates: &[&[&str]] = &[
            &["wl-copy"],
            &["xclip", "-selection", "clipboard"],
            &["xsel", "--clipboard", "--input"],
        ];

        for args in candidates {
            let mut cmd = Command::new(args[0]);
            if args.len() > 1 {
                cmd.args(&args[1..]);
            }
            let child = cmd.stdin(Stdio::piped()).stderr(Stdio::null()).spawn();
            if let Ok(mut c) = child {
                if let Some(stdin) = c.stdin.as_mut() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                if let Ok(status) = c.wait() {
                    if status.success() {
                        return;
                    }
                }
            }
        }
        tracing::warn!(
            "panoya kopyalama başarısız — yardımcı araç (wl-copy/xclip/xsel/pbcopy) bulunamadı"
        );
    }
}

// ---------------------------------------------------------------------------
// Windows helpers (windows-rs ile native API)
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
pub(crate) mod win {
    use super::*;
    use std::cell::Cell;
    use windows::core::{Result, GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::Com::{
        CoInitializeEx, CoTaskMemFree, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
    use windows::Win32::UI::Shell::{
        ILCreateFromPathW, ILFree, SHGetKnownFolderPath, SHOpenFolderAndSelectItems, ShellExecuteW,
        KF_FLAG_DEFAULT,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// UTF-16 LE null-terminated vektör üretir.
    /// `pub(crate)` — ui.rs (MessageBoxW) ve main.rs (Registry) de kullanır.
    pub(crate) fn to_wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    /// `OsStr` → UTF-16 LE null-terminated. `encode_wide()` lossless (path'te
    /// non-UTF8 byte'lar da doğru kodlanır); `path.display()` lossy olabilir.
    fn to_wide_os(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        let mut v: Vec<u16> = s.encode_wide().collect();
        v.push(0);
        v
    }

    /// `SHGetKnownFolderPath` → PathBuf. Çıktı bellek `CoTaskMemFree` ile serbest
    /// bırakılır (aksi halde leak). Bellek tahsisi başarısızsa `None`.
    pub(super) fn known_folder(folder: &GUID) -> Option<PathBuf> {
        // SAFETY: `folder` is a valid GUID reference from the caller.
        // `SHGetKnownFolderPath` on success writes a freshly CoTaskMem-
        // allocated, null-terminated UTF-16 string whose ownership we take
        // via `pwstr`. We null-check before deref, compute `len` with
        // `PCWSTR::len()` (stops at the NUL the API writes), build a
        // read-only slice bounded by that `len`, copy it into an
        // `OsString` via `from_wide`, and only then release the buffer
        // with the matching allocator `CoTaskMemFree`. No dangling
        // reference escapes the block.
        unsafe {
            // windows-rs 0.60: flag enum doğrudan geçilir (eski sürümlerde u32).
            let pwstr: PWSTR = SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None).ok()?;
            if pwstr.is_null() {
                return None;
            }
            // PCWSTR::from_raw(...).len() — null'a kadar sayan idiomatic yol.
            let len = windows::core::PCWSTR::from_raw(pwstr.0).len();
            let slice = std::slice::from_raw_parts(pwstr.0, len);
            let os = {
                use std::os::windows::ffi::OsStringExt;
                std::ffi::OsString::from_wide(slice)
            };
            CoTaskMemFree(Some(pwstr.0 as _));
            Some(PathBuf::from(os))
        }
    }

    /// Bilgisayar DNS hostname'i. Başarısızsa `None`.
    pub(super) fn computer_name() -> Option<String> {
        // SAFETY: `buf` is a heap `Vec<u16>` of 256 elements owned for the
        // full call. We pass a `PWSTR` pointing at its start together with
        // `&mut size` giving the API the exact capacity in wide chars.
        // `GetComputerNameExW` writes at most `size` wide chars and
        // updates `size` to the count excluding the NUL, so
        // `buf.truncate(size)` stays within bounds. No other reference
        // aliases `buf` during the FFI call, and `&mut size` is the
        // exclusive borrow of a local.
        unsafe {
            let mut size: u32 = 256;
            let mut buf = vec![0u16; size as usize];
            // windows-rs 0.60: lpbuffer `Option<PWSTR>` (NULL desteği için).
            if GetComputerNameExW(
                ComputerNameDnsHostname,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut size,
            )
            .is_err()
            {
                return None;
            }
            buf.truncate(size as usize);
            let os = {
                use std::os::windows::ffi::OsStringExt;
                std::ffi::OsString::from_wide(&buf)
            };
            os.into_string().ok()
        }
    }

    thread_local! {
        /// Bu thread'de `CoInitializeEx` çağrıldı mı?
        ///
        /// `CoInitializeEx` S_OK/S_FALSE döndüğünde thread-başına ref count
        /// artırıyor. Tekrar çağrı ref count'u şişirir; `CoUninitialize`
        /// çağırmadığımız için birikmesin diye flag tutup bir kez çağırıyoruz.
        static COM_INITED: Cell<bool> = const { Cell::new(false) };
    }

    /// COM'u apartment-threaded modda thread başına bir kez başlatır.
    ///
    /// `S_OK` (ilk init) veya `S_FALSE` (zaten init) veya `RPC_E_CHANGED_MODE`
    /// (başka modda init) kabul edilir; OOM vb. gerçek hata durumlarında
    /// `COM_INITED` flag `true` yapılmaz, sonraki çağrı retry eder.
    /// Process yaşam süresi boyunca init kalır; `CoUninitialize` çağırmayız
    /// (uygulama kapanışında OS temizler).
    fn ensure_com_init() {
        COM_INITED.with(|flag| {
            if flag.get() {
                return;
            }
            // SAFETY: `CoInitializeEx` takes no pointer inputs from us —
            // the first argument is `None` (reserved) and the second is a
            // bitflag value. It is documented by MSDN as callable from any
            // thread; thread-safety is handled by COM itself. We inspect
            // the returned HRESULT below and only mark `COM_INITED` once
            // per thread so the per-thread COM ref-count does not grow.
            let hr =
                unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
            // windows-rs `HRESULT` → `ok()` S_OK/S_FALSE'ı tamam sayar,
            // gerçek hataları `Err` olarak geri verir. RPC_E_CHANGED_MODE da
            // kabul: COM zaten farklı modda init — bizim için OK.
            // SAFETY-CAST: HRESULT bit pattern kasıtlı u32 → i32 reinterpretation
            // (high-bit error encoding). `cast_signed()` Rust 1.85+ stable
            // (MSRV 1.90 ≥ kullanılabilir); `as i32` yerine lint-clean alternatif.
            const RPC_E_CHANGED_MODE: windows::core::HRESULT =
                windows::core::HRESULT(0x80010106u32.cast_signed());
            if hr.is_ok() || hr == RPC_E_CHANGED_MODE {
                flag.set(true);
            } else {
                tracing::warn!("CoInitializeEx başarısız: {:?}", hr);
            }
        });
    }

    /// `ShellExecuteW` ile "open" verb'ü çağır. URL / dosya / klasör hepsi kabul.
    pub(super) fn shell_execute_open(target: &std::ffi::OsStr) {
        let wide = to_wide_os(target);
        let verb = to_wide("open");
        // SAFETY: `wide` and `verb` are local `Vec<u16>`s, both NUL-
        // terminated by `to_wide*` and kept alive for the whole call
        // (they are dropped at end-of-scope, after `ShellExecuteW`
        // returns). The `PCWSTR`s read at most until the embedded NUL;
        // the remaining arguments are `PCWSTR::null()`, documented as
        // valid for "no parameters / default directory". `ShellExecuteW`
        // is synchronous w.r.t. its argument reads, so neither buffer is
        // touched after return.
        unsafe {
            let _ = ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(wide.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );
        }
    }

    /// Dosya Explorer'da seçili olarak açılır — `SHOpenFolderAndSelectItems`.
    /// PIDL'ı `ILCreateFromPathW` ile alır, kullanım sonrası `ILFree` ile
    /// serbest bırakır. COM init gereklidir.
    pub(super) fn select_in_explorer(path: &Path) -> Result<()> {
        ensure_com_init();
        let wide = to_wide_os(path.as_os_str());
        // SAFETY: COM is initialised for this thread by `ensure_com_init`
        // above — precondition of both APIs used here. `wide` is a local
        // NUL-terminated UTF-16 buffer alive for the whole block. On
        // success `ILCreateFromPathW` returns a PIDL we own; we null-
        // check it before use and always free it with the matching
        // `ILFree` on both success and error paths of
        // `SHOpenFolderAndSelectItems`. The call only reads the PIDL
        // and returns a `Result`; no reference escapes.
        unsafe {
            let pidl = ILCreateFromPathW(PCWSTR(wide.as_ptr()));
            if pidl.is_null() {
                return Err(windows::core::Error::from_win32());
            }
            let result = SHOpenFolderAndSelectItems(pidl, None, 0);
            ILFree(Some(pidl));
            result
        }
    }

    /// Clipboard'a UTF-16 metin koyar.
    ///
    /// Akış: OpenClipboard → EmptyClipboard → GlobalAlloc+Lock → copy →
    /// Unlock → SetClipboardData(CF_UNICODETEXT) → CloseClipboard.
    ///
    /// SetClipboardData başarılıysa hafızanın sahipliği clipboard'a geçer —
    /// biz free ETMEYİZ. Her hata yolunda `GlobalFree` ile kaynak serbest
    /// bırakılır; `OpenClipboard` başarısız olursa da alloc'u temizleriz.
    pub(super) fn clipboard_set(text: &str) -> Result<()> {
        // `CF_UNICODETEXT = 13` — Windows clipboard formatı, MSDN'de stabil
        // dokümante. windows-rs 0.60'ta `Win32::System::Ole` modülünde ama
        // `Win32_System_Ole` feature ağır; bu tek sabit için dep bloat'ına
        // değmez. Hardcoded sabit korunur.
        const CF_UNICODETEXT: u32 = 13;
        let wide = to_wide(text);
        let bytes = wide.len() * std::mem::size_of::<u16>();

        // SAFETY: This block drives the documented Win32 clipboard
        // protocol. `wide` is a local NUL-terminated `Vec<u16>` alive for
        // the full block; `bytes` is its exact byte length. Each raw-
        // pointer op respects its precondition:
        //   - `GlobalAlloc(GMEM_MOVEABLE, bytes)` returns an owned HGLOBAL
        //     or NULL (handled); we free it via `GlobalFree` on every
        //     error path.
        //   - `GlobalLock(hmem)` yields a pointer valid for `bytes` bytes
        //     until the matching `GlobalUnlock`; we null-check, copy
        //     exactly `wide.len()` u16s (non-overlapping, within size),
        //     then Unlock before releasing the lock.
        //   - `OpenClipboard`/`EmptyClipboard`/`CloseClipboard` take no
        //     pointer inputs; errors free `hmem` and close the clipboard.
        //   - On `SetClipboardData` success the clipboard takes ownership
        //     of `hmem` — we must not free it. On failure we free.
        // Net effect: `hmem` is freed exactly once on every error path
        // and transferred to the clipboard on the success path, so no
        // leak and no double free.
        unsafe {
            let hmem = GlobalAlloc(GMEM_MOVEABLE, bytes)?;
            if hmem.0.is_null() {
                return Err(windows::core::Error::from_win32());
            }

            let dst = GlobalLock(hmem) as *mut u16;
            if dst.is_null() {
                let _ = GlobalFree(Some(hmem));
                return Err(windows::core::Error::from_win32());
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
            let _ = GlobalUnlock(hmem);

            // Clipboard sahipliğini al. Başarısızsa hafıza sızmasın diye
            // GlobalFree ile kapat.
            if let Err(e) = OpenClipboard(None) {
                let _ = GlobalFree(Some(hmem));
                return Err(e);
            }
            // EmptyClipboard hata yoluyla SetClipboardData da bozulur;
            // failure olursa kaynakları temiz bırak.
            if let Err(e) = EmptyClipboard() {
                let _ = CloseClipboard();
                let _ = GlobalFree(Some(hmem));
                return Err(e);
            }
            // windows-rs 0.60: hmem `Option<HANDLE>` (NULL = clear format data).
            match SetClipboardData(CF_UNICODETEXT, Some(HANDLE(hmem.0 as _))) {
                Ok(_) => {
                    // Sahipliği clipboard aldı; free ETMEYİZ.
                    let _ = CloseClipboard();
                    Ok(())
                }
                Err(e) => {
                    // Sahipliği transfer başarısız — biz free ederiz.
                    let _ = CloseClipboard();
                    let _ = GlobalFree(Some(hmem));
                    Err(e)
                }
            }
        }
    }

    /// Clipboard'dan UTF-16 metni okur; UTF-8 string'e `from_utf16_lossy`
    /// ile çevirir.
    ///
    /// Dönüş semantiği:
    ///   - `Ok(Some(s))`: Clipboard'da CF_UNICODETEXT formatı var ve başarıyla okundu.
    ///   - `Ok(None)`: Pano metin formatı içermiyor (`GetClipboardData` başarısız).
    ///   - `Err(_)`: `OpenClipboard`/`GlobalLock`/`GlobalSize` gibi Win32 API
    ///     hataları — caller handle'layabilsin.
    ///
    /// SECURITY: CF_UNICODETEXT MSDN spec'i gereği NUL-terminated, ama yine
    /// de `GlobalSize` ile hafıza blokunun gerçek üst sınırını alıp okumayı
    /// buraya clamp ediyoruz (malformed/oob handle'da buffer over-read yok).
    pub(super) fn clipboard_get() -> Result<Option<String>> {
        const CF_UNICODETEXT: u32 = 13;
        // SAFETY: OpenClipboard alır → GetClipboardData handle'ı döner (sahiplik
        // clipboard'ta kalır, biz sadece okuruz). GlobalLock → sabit pointer.
        // Okunacak u16 sayısı MIN(GlobalSize/2, PCWSTR::len()) — iki bağımsız
        // üst sınır, ikisi de NUL'a kadar garanti verir. GlobalUnlock ve
        // CloseClipboard her yoldan çağrılır; handle'ın sahipliği clipboard'ta.
        unsafe {
            OpenClipboard(None)?;
            let Ok(handle) = GetClipboardData(CF_UNICODETEXT) else {
                let _ = CloseClipboard();
                return Ok(None);
            };
            let hglobal = HGLOBAL(handle.0 as _);
            let ptr = GlobalLock(hglobal) as *const u16;
            if ptr.is_null() {
                let _ = CloseClipboard();
                return Err(windows::core::Error::from_win32());
            }
            // GlobalSize bayt döner; u16 slot sayısına çevir.
            let size_bytes = GlobalSize(hglobal);
            let max_u16 = if size_bytes >= 2 { size_bytes / 2 } else { 0 };
            // İkinci üst sınır: NUL'a kadar say. İkisi de NUL/OOM'a karşı savunma.
            let nul_len = PCWSTR::from_raw(ptr).len();
            let len = nul_len.min(max_u16);
            let slice = std::slice::from_raw_parts(ptr, len);
            let s = String::from_utf16_lossy(slice);
            let _ = GlobalUnlock(hglobal);
            let _ = CloseClipboard();
            Ok(Some(s))
        }
    }
}
