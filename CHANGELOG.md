# Changelog

All notable changes to HekaDrop will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-04-19

**⚠️ Security hotfix** — v0.5.0 kullanıcıları hemen güncellemelidir.

### Security
- **[CVE kapsamında Critical] Path traversal**: Uzak cihazdan gelen
  `FileMetadata.name` alanı sanitize edilmeden kullanılıyordu; `..\..\..\path`
  veya absolute path'lerle `~/Downloads` dışına dosya yazılabiliyordu.
  `auto_accept=true` veya trusted device yolunda autostart konumlarına
  yazılarak RCE'ye çevrilebilirdi. `sanitize_received_name()` eklendi:
  basename-only, reserved adlar, NUL/control filter, 200-byte UTF-8 limit.
- **[CVE kapsamında Critical] URL scheme allow-list**: `TextType::Url`
  payload `open_url()`'a doğrudan gidiyordu; `javascript:`, `file://`,
  `smb://` (NTLM leak), `ms-msdt:` ve özel protocol handler'lar
  exploit'e açık idi. `is_safe_url_scheme()` yalnız `http://`/`https://`
  kabul eder; diğerleri clipboard'a kopyalanır ve kullanıcıya bildirilir.

### Added
- 12 birim test: sanitize (Unix/Windows traversal, NUL, reserved names,
  UTF-8 boundary, Türkçe); url scheme (safe http/https + unsafe
  javascript/file/smb/data/vbscript/ms-msdt/zoom-us).

## [0.5.0] - 2026-04-19

Projenin public yayın sürümü. Paketleme, lokalizasyon ve UX
iyileştirmeleriyle v0.4.0 üzerine birikmiş işleri topluyor.

### Added
- **i18n**: Türkçe + İngilizce UI (`src/i18n.rs`); `HEKADROP_LANG` /
  `LC_ALL` / `LC_MESSAGES` / `LANG` üzerinden dil algılama; `t()` / `tf()`
  API; 60+ key; tray menu, dialog, bildirim ve zaman gösterimi çevrilmiş
- **Klasör drag-drop**: pencereye bırakılan klasörler recursive olarak
  düzleştirilip transfer listesine eklenir (symlink döngüsü koruması var)
- **Paketleme**: Homebrew cask (`Casks/hekadrop.rb`) v0.5.0 ile güncel,
  Scoop manifest (`scoop/hekadrop.json`) — Windows için
- **Community health**: `SECURITY.md` + `.en.md`, `CODE_OF_CONDUCT.md` +
  `.en.md` (iki dilli), issue template'leri (bug / feature) + PR template,
  `config.yml` (Advisories / Discussions yönlendirme, blank issue kapalı)

### Changed
- `dialog.update.failed` metni nötrleştirildi — "repo özel ise bu normal"
  ifadesi public repo için geçerli değil artık
- `notify.transfer_cancelled` yeni key — "iptal istendi" yerine tamamen
  iptal edilmiş durumlar için ayrı mesaj
- osascript onay dialog'u buton metni `"button returned:"` prefix ile
  kontrol ediliyor — lokalize label'larda substring collision olmuyor
- i18n `tf()` single-pass parser — args içinde `{N}` olması durumunda
  double-replace bug'ı yok

### Fixed
- Linux zenity `--column=` device header artık lokalize
- Windows MessageBoxW hint redundancy ("Kabul et + Kabul + güven" gibi
  çift yazımlar giderildi)

## [0.4.0] - 2026-04-19

Üçüncü platform — Windows. HekaDrop artık macOS / Linux / Windows üzerinde
çalışır; çekirdek Quick Share protokolü üç platformda da aynı.

### Added
- Windows portu: native Win32 / WinRT katmanı
  - `windows-rs` 0.60 ile `SHGetKnownFolderPath` (config/logs/downloads),
    `GetComputerNameExW` (cihaz adı), `ShellExecuteW` (open/url),
    `SHOpenFolderAndSelectItems` + `ILCreateFromPathW` (reveal),
    `OpenClipboard` + `SetClipboardData(CF_UNICODETEXT)` (UTF-16 doğru,
    `clip.exe`'nin ANSI bozulması yok), `RegOpenKeyExW`/`RegSetValueExW`
    (autostart)
  - UI: `MessageBoxW` PIN onay dialog; `notify-rust` WinRT toast
  - File/folder/device seçimi: PowerShell + `System.Windows.Forms` (UTF-8
    stdout encoding ile Türkçe karakterler bozulmaz)
  - `thread_local!` guard ile `CoInitializeEx` thread başına tek çağrı
- Windows CI job'u (`windows-latest`): fmt / clippy / test / release build
  + `.exe` artifact upload
- Windows'a özgü `notify-rust` + `windows` crate `[target.'cfg(...)']`
  dependency bölümü

### Changed
- Platform abstraction `mod win` `pub(crate)` — Windows helper'ları
  (`to_wide`, known folder, clipboard) crate genelinde kullanılabilir
- `toggle_login_item` artık üç platformda: macOS launchd, Linux systemd
  `--user`, Windows Registry `HKCU\...\Run`

### Fixed
- `path_to_file_uri` — D-Bus `ShowItems` URI'sinde RFC 3986 encoding
  (0.3.0 commit'i) buraya taşındı (doğru cfg altında)
- Proto modüllerine `rustdoc::invalid_html_tags` ve
  `rustdoc::broken_intra_doc_links` allow — auto-generated `<TYPE>`
  etiketleri rustdoc'u kırmasın
- `settings.rs` intra-doc link'leri `Self::` prefix'i ile explicit
- `config.rs` `endpoint_info` byte layout brackets backticks içinde
  (rustdoc `[17]`'yi intra-doc link sanmasın)

## [0.3.0] - 2026-04-19

İkinci platform — Linux. Çekirdek Quick Share protokolü değişmedi; UI / path /
autostart katmanları `cfg`-gated cross-platform hale geldi.

### Added
- Integration test suite (unit + protocol-compliance) kapsayan end-to-end senaryolar
- Strict clippy + coverage + rustdoc CI workflow'ları (`ci.yml`, `coverage.yml`, `docs.yml`)
- `TrustedDevice` struct (name + endpoint ID hash) — legacy string tabanlı whitelist'in yerini alır
- Assembler GC — yarıda kalan (orphan) partial payload'lar için temizlik
- Sender progress otomatik `Idle` sıfırlaması (tamamlanmadan 3 sn sonra)
- Codecov raporu + badge entegrasyonu
- Criterion benchmark iskeleti (`bench.yml`)
- Rustdoc yayın adımı GitHub Pages'e
- Linux portu: GTK3 + WebKit2GTK + AppIndicator tray; zenity/kdialog dialog; systemd user service autostart
- Sabit TCP port 47893 (HEKADROP_PORT env ile override'lanabilir) — firewall kurallarını kolaylaştırır
- Platform abstraction modülü (`src/platform.rs`) — cross-platform path/device-name/open/clipboard
- Alınan dosya bildiriminde aksiyon butonları (Aç / Klasörde göster) — Linux'ta D-Bus, macOS'ta düz bildirim
- mDNS yayın filtresi: Docker/virbr/tailscale sanal arayüzleri hariç bırakılır (yanlış IP çözümlenmesini önler)
- Makefile'a Linux hedefleri: `install-linux`, `install-linux-system`, `uninstall-linux`, `deb`
- Cargo.toml `[package.metadata.deb]` — cargo-deb ile paket üretimi
- Ubuntu `test-linux` CI job'u + `.deb` artifact upload

### Changed
- `Settings` yapısı JSON migration ile geri uyumlu (eski alanlar opsiyonel)
- Rate limiter trusted cihazlar için bypass yolunu erken adımda kestirir (daha az kilit tutma)
- Progress yayınları debounce (UI'ya yansıyan event sayısı azaltıldı)
- Config/log yolları XDG uyumlu (`~/.config/HekaDrop`, `~/.local/state/HekaDrop/logs`); macOS'ta `~/Library/...` aynı kalır
- Cihaz adı platform-aware: macOS'ta `scutil`, Linux'ta `/etc/hostname`
- mDNS `advertise` artık `Result<Option<MdnsHandle>>` döner — uygun IPv4 yoksa UI çalışır, mDNS sessizce devre dışı
- `toggle_login_item` artık Linux ve macOS destekli (systemd `--user` + launchd); Windows ve diğer platformlar için no-op stub

### Fixed
- Reject sonrası pending destination temizliği (orphan dosyalar geride kalmıyordu)
- `total_bytes=0` sender edge case — boş dosya gönderimi açıkça reddedilir (division-by-zero panic riski kalktı), multi-file `i64` overflow koruması eklendi
- Unknown trusted device isim çakışması (endpoint ID hash ile ayrıştırıldı)
- `FileSink.written` ölü kod temizliği
- mDNS kapatılırken servis kaydı düşürülmeyen nadir race condition
- D-Bus `FileManager1.ShowItems` URI'si RFC 3986 percent-encoding — boşluk / `#` / `?` / `%` / Türkçe karakterli dosya adları için doğru URI üretilir
- `HEKADROP_PORT=0` değeri artık filtrelenir — "sabit port" semantiği korunur

### Security
- Sequence number doğrulaması çift yönlü (hem alıcı hem gönderici tarafında)
- HMAC doğrulaması sabit-zamanlı karşılaştırma (`subtle`) ile

## [0.1.0] - 2026-04-18

İlk yayın — macOS universal2 binary, Homebrew cask, menu bar UI, SHA-256 integrity.

### Added
- Google Quick Share protokolüne (UKEY2 + AES-256-CBC + HMAC-SHA256) uyumlu alıcı ve gönderici
- mDNS/Bonjour keşfi (`_FC9F5ED42C8A._tcp.local.`)
- Trusted devices (whitelist) — rate limit muafiyetli otomatik kabul
- Rate limiter (60 sn pencere / IP başına 10 bağlantı) — trusted cihazlar hariç
- İstatistikler: toplam byte, dosya sayısı, cihaz bazlı kırılım
- Tanı sekmesi (diagnostics) — çalışan servis durumu + kullanım istatistikleri
- Log rotation: günlük dosya + maksimum 3 gün saklama + 10 MB üst sınır truncate
- Aktif aktarımlar için iptal (cancel) desteği
- Universal2 binary (x86_64 + aarch64 tek dosyada)
- Homebrew cask (`Casks/hekadrop.rb`)
- macOS menu bar UI (tao event loop + wry WebView)
- SHA-256 integrity — alınan her dosyanın hash'i doğrulanır
- Otomatik güncelleme kontrolü (GitHub Releases API üzerinden)
- Tab'lı pencere: Ana / Geçmiş / Ayarlar / Tanı
- 4 haneli PIN + native onay dialog'u
- Disk-stream kaydetme (büyük dosyalarda bellek baskısı yok)
- JSON konfigürasyon: `~/Library/Application Support/HekaDrop/config.json`
- DMG paketleme + launchd user agent
- GitHub Actions CI + Release otomasyonu (Node 24, actions v5)

### Security
- Her oturum için ephemeral P-256 anahtar çifti
- MITM koruması: iki cihazda eşleşen 4 haneli PIN
- Replay koruması: sequence counter ile HMAC doğrulaması
- Trafik hiçbir sunucuya uğramaz — yalnız yerel ağ

[Unreleased]: https://github.com/YatogamiRaito/HekaDrop/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/YatogamiRaito/HekaDrop/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/YatogamiRaito/HekaDrop/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/YatogamiRaito/HekaDrop/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/YatogamiRaito/HekaDrop/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/YatogamiRaito/HekaDrop/releases/tag/v0.1.0
