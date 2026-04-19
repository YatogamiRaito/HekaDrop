# Changelog

All notable changes to HekaDrop will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security (v0.6 hotfix #2 — PR #35 review aftermath)
- **[HIGH] Legacy spoofing vektörü kapatıldı** (`connection.rs` —
  PR #35 review, Copilot). PR #35'in ilk fix'i trust kararını
  `is_trusted_by_hash(h) || is_trusted_legacy(name, id)` yapıyordu;
  bu attacker'ın kurbanın (name, id)'sini spoof edip kendi hash'ini
  auto-accept + opportunistic upgrade ile legacy kayda kalıcı olarak
  bağlamasına izin veriyordu. Trust kararı artık **strict hash-first**:
  peer hash gönderdiyse YALNIZ hash eşleşmesi trusted sayılır; legacy
  fallback yalnız pre-v0.6 peer (hash göndermeyen) için geçerli.
  Legacy kullanıcıların migration bedeli: ilk v0.6 bağlantısında
  one-time dialog — Accept sonrası opportunistic upgrade hash'i bağlar,
  sonraki bağlantılar dialog'suz.
- **[MED] HTML attribute escape fix** (`resources/window.html` —
  PR #35 review, Gemini). `escapeAttr()` önceden tek tırnakları `\'`
  (JS string escape syntax'ı) ile kaçırıyordu — HTML için yanlış.
  Ekran okuyucular ters bölüyü okuyabiliyordu. Doğru HTML entity
  escape'ine (`&amp; &quot; &lt; &gt;`) geçildi.
- **[MED] `tf()` placeholder dedup** (`resources/window.html` —
  PR #35 review, Gemini). `tf()` artık `t.apply` ile `t()`'nin regex
  tabanlı substitution'ına delege eder; iki ayrı implementasyon bakımı
  bitti.
- **[MED] `0o600` test umask-tolerant** (`src/settings.rs` — PR #35
  review, Copilot). `atomic_write_mode` testi exact `0o600` yerine
  "group/world erişim yok" (`mode & 0o077 == 0`) invariant'ını
  kontrol eder — hardened umask ortamlarında (0o077/0o277) owner
  bitleri daha da kısıtlansa bile security invariant'ı doğrular.

### Security (MAJOR — v0.6.0)
- **[HIGH] Trusted device identity hardening** (Issue #17): trust
  kararı artık `PairedKeyEncryption.secret_id_hash` (6 byte,
  device-stable HKDF türetmesi) üzerinden veriliyor; `endpoint_id`
  (4 ASCII byte, spoofable) yalnızca yardımcı bilgi. 7 gün TTL —
  `trust_ttl_secs` Settings ayarıyla override edilebilir. Legacy
  (name, id) kayıtları opportunistic upgrade yolu ile yeni kimliğe
  bağlanır; üç sürüm boyunca legacy fallback açık kalır, v0.7'de
  kaldırılacak.
- `src/identity.rs` — yeni cihaz kimlik dosyası
  (`config_dir()/identity.key`, POSIX 0600 izinli). `DeviceIdentity`
  32 bayt rastgele uzun-süreli anahtarı tutar; `secret_id_hash()`
  HKDF-SHA256 ile türetilir, cihaz değişmediği sürece stabil kalır.

### Changed
- `Settings.trust_ttl_secs` — yeni alan, varsayılan 7 gün (604800 sn).
  `0` değeri TTL'i devre dışı bırakır (önerilmez).
- `TrustedDevice.secret_id_hash` + `trusted_at_epoch` — yeni alanlar.
  Eski JSON şemaları `#[serde(default)]` ile `None`/`0` olarak okunur.
- `Settings::is_trusted_by_hash` / `is_trusted_legacy` /
  `add_trusted_with_hash` / `touch_trusted_by_hash` /
  `prune_expired` — v0.6 trust API'si. Eski `is_trusted` +
  `add_trusted` legacy uyumluluk için korundu, v0.7'de kaldırılacak.
- `connection.rs` peer `secret_id_hash`'i yakalayıp hash-first trust
  lookup yapıyor; kabul sonrası legacy kayıtlar opportunistic olarak
  yeni kimliğe bağlanır (`info!` log).

### Documentation
- `docs/design/017-trusted-id-hardening.md` — Issue #17 tasarım belgesi
  (**Status: Accepted 2026-04-20**, v0.6.0'da shipped). §9 açık
  soruları reviewer onayıyla cevaplandı: TTL=7 gün (override'lı),
  signed_data doğrulaması v0.7'ye ertelendi, sender'da TTL yok, legacy
  log level=info!, hash algoritması HKDF-SHA256.

### Changed (accessibility)
- Webview CSS tokenized via CSS custom properties (`--bg-*`, `--fg-*`,
  `--accent`, `--danger`, `--border*`). Dark palette unchanged by
  default; `prefers-color-scheme: light` now renders a WCAG 2.1 AA
  conformant light theme. `forced-colors: active` uses system colors.
  Explicit override via `<html data-theme="light|dark">` for future
  Settings-driven toggle.

### Changed (release infrastructure)
- Release workflow now publishes Windows `.exe` + Linux `.deb` in
  addition to macOS `.dmg` (+ source tarball). Scoop install
  (`scoop/hekadrop.json`) becomes functional for the next tag.
- `CHECKSUMS.txt` consolidated across platforms by a `publish-release`
  job that waits for all three build jobs.

### Changed (performance)
- `payload.rs`: file I/O migrated to `tokio::fs` — receiver thread no
  longer blocks on disk writes; large-file transfers don't starve the
  reactor (prevents keepalive timeout false-positives on slow disks).
- `server.rs` + `sender.rs`: `TCP_NODELAY` set on accepted + outbound
  sockets — handshake latency down by 1-2 × RTT × 200ms-Nagle-delay on
  local networks.

## [0.5.2] - 2026-04-19

Kapsamlı güvenlik + altyapı sertleştirme sürümü. İki tur derinlemesine
araştırma ajanı raporuyla (toplam 12 rapor, 35+ bulgu) belirlenen **High
+ Medium** ağırlıklı 10+ güvenlik açığı ve 10 AI review yorumu bu
sürümde adreslendi. v0.5.1 kullanıcılarının güncellenmesi önerilir —
DoS yüzeyi, TOCTOU ve log PII sızıntıları giderildi.

### Security (HIGH batch — ilk tur araştırma)
- **PIN clear-text log kaldırıldı**: 4 basamaklı PIN'in SHA-256 özeti
  dahi brute-force edilebilir; log fingerprint'i artık 256-bit auth_key
  üzerinden (`session_fingerprint`) alınıyor. (Gemini review'ı
  sonrası `pin_fingerprint` tamamen kaldırıldı.)
- **UKEY2 cipher downgrade koruması**: Peer `Ukey2ServerInit` içinde
  P256_SHA512 dışında cipher seçerse veya version != 1 ise bail.
  Önceki kod herhangi bir cipher'ı kabul ediyordu.
- **BYTES payload 4 MiB cap** (`MAX_BYTES_BUFFER`): Sonsuz BYTES
  payload'ı yollayan peer artık bellek tüketemez.
- **Eşzamanlı bağlantı limiti** (`MAX_CONCURRENT_CONNECTIONS = 32`):
  `tokio::sync::Semaphore` + `try_acquire_owned` ile bloksuz reddetme.

### Security (HIGH + MED batch — ikinci tur araştırma)
- **Slow-loris DoS koruması**: `frame::read_frame` deadline'sız
  `read_exact` kullanıyordu; handshake frame'lerine 30 sn,
  steady-loop'a 60 sn `tokio::time::timeout` eklendi
  (`HekaError::ReadTimeout`).
- **Protobuf cardinality flood**: `prost` repeated alan sınırı
  koymuyor. `Ukey2ClientInit.cipher_commitments` ≤8,
  `Introduction.file_metadata` ≤1000, `text_metadata` ≤64 guard'ı.
- **`unique_downloads_path` TOCTOU**: İki paralel receiver aynı dosya
  adını "mevcut değil" görüp aynı path'e `File::create` (O_TRUNC)
  yapabiliyordu — ilki yazdığı veriyi ikincisi siliyordu. Artık
  `OpenOptions::create_new(true)` ile **atomik** reserve (POSIX
  `O_EXCL` / Win `CREATE_NEW`). İkinci alıcı sonraki isme geçer.
- **`Settings` + `Stats` save atomic değildi + RwLock altında senkron
  disk I/O**: `atomic_write` (tmp+rename, POSIX + `MoveFileExW` Windows)
  + `SETTINGS_DISK_LOCK` / `STATS_DISK_LOCK` + snapshot-clone-then-save
  pattern ile crash-safe + UI-donma-proof hale getirildi.
- **`SecureCtx` sequence counter i32 overflow**: Crafted peer
  `sequence_number = i32::MAX` yollayıp debug build'i panic'letebilir
  veya release'te wrap'letebilirdi. `checked_add` ile bail.
- **Duplicate `payload_id` silent overwrite**: Saldırgan Introduction'da
  aynı id ile iki FileMetadata yollayıp UI'ın "legit.pdf" onayını
  "_evil.sh" yazmaya çevirebilirdi. `register_file_destination` artık
  ikinci kaydı reddediyor.
- **Payload overrun + silent truncation**: `total_size` sonraki
  chunk'larda doğrulanmıyordu; cumulative `written <= total_size` +
  1 TiB `MAX_FILE_BYTES` cap + last-chunk eşitlik kontrolü eklendi.
- **Symlink reject + `sync_all` hata propagation**: İlk chunk açarken
  `symlink_metadata` ile symlink reddi, disk senkronizasyon hataları
  sessizce yutulmuyor.
- **Placeholder cleanup**: Kullanıcı reddettiğinde / peer iptal
  ettiğinde `unique_downloads_path`'in yarattığı 0-bayt placeholder'lar
  diskten silinir.

### Changed (privacy)
- **Log PII redaction**: Log dosyası artık full path yerine basename,
  64-hex SHA yerine ilk 16 hex, URL query'si yerine `scheme://host`
  yazıyor. Gerekçe: 3 gün log retention + ad-hoc log paylaşımı
  (GitHub issue, destek) dizin yapısını, cross-user dosya fingerprint
  ve URL query token'larını sızdırmamalı. UI bildirimleri (kullanıcının
  kendi verisi) değişmedi.

### Changed (supply chain)
- Dependabot konfigürasyonu (cargo + github-actions haftalık).
- `cargo-audit` GitHub Actions workflow'u (haftalık + Cargo.lock
  değişiminde).
- `cargo-deny` konfigürasyonu (`deny.toml`) + workflow: license /
  advisory / source / wildcard policy. 14 pre-existing transitive
  advisory (gtk3-rs ailesi) gerekçeli ignore edildi; upstream
  `gtk4-rs` geçişinde silinecek.

### Documentation
- `src/platform.rs` 6 Windows FFI unsafe bloğuna `// SAFETY:`
  gerekçesi eklendi (Rust idiom). Davranış değişikliği yok.

### Added
- 14 yeni security regression testi (`duplicate_payload_id_reddedilir`,
  `file_overrun_reddedilir`, `file_last_chunk_truncation_reddedilir`,
  `file_negative_total_size_reddedilir`, `encrypt_overflow_guardlu`,
  `cipher_commitments_flood_reddedilir`, `atomic_write` overwrite +
  tmp-leak guards + concurrent same-pid, symlink reject, 1 TiB cap,
  pending-destination cleanup, log redact helpers). Toplam test: **126
  birim + integration**.
- `src/log_redact.rs` — `redact_path`, `redact_sha`, `redact_url`
  pub(crate) helper'ları.
- `src/settings.rs::atomic_write` — platform-aware tmp+rename +
  scope-guard cleanup + unique pid+rand tmp naming.

### Changed (build deps — Dependabot)
- `actions/deploy-pages` 4 → 5
- `codecov/codecov-action` 5 → 6
- `actions/configure-pages` 5 → 6

## [0.5.1] - 2026-04-19

**⚠️ Security hotfix** — v0.5.0 kullanıcıları hemen güncellemelidir.

### Security
- **[Critical security fix] Path traversal**: Uzak cihazdan gelen
  `FileMetadata.name` alanı sanitize edilmeden kullanılıyordu; `..\..\..\path`
  veya absolute path'lerle `~/Downloads` dışına dosya yazılabiliyordu.
  `auto_accept=true` veya trusted device yolunda autostart konumlarına
  yazılarak RCE'ye çevrilebilirdi. `sanitize_received_name()` eklendi:
  basename-only, reserved adlar (+ `CONIN$`/`CONOUT$`/`CLOCK$`, çoklu
  uzantı + trailing dot bypass), NUL/control + Windows yasaklı
  karakterler (`<>:"/\\|?*` — özellikle NTFS ADS için `:`), 200-byte
  UTF-8 limit.
- **[Critical security fix] URL scheme allow-list**: `TextType::Url`
  payload `open_url()`'a doğrudan gidiyordu; `javascript:`, `file://`,
  `smb://` (NTLM leak), `ms-msdt:` ve özel protocol handler'lar
  exploit'e açık idi. `is_safe_url_scheme()` yalnız `http://`/`https://`
  kabul eder; diğerleri clipboard'a kopyalanır ve kullanıcıya bildirilir.
- CVE ID'leri GitHub Security Advisory publish edildikten sonra bu
  entry'ye eklenecek.

### Added
- 16 birim test: sanitize (Unix/Windows traversal, NUL, reserved names
  + çoklu uzantı, CONIN$/CONOUT$/CLOCK$, trailing dot/space bypass,
  NTFS ADS + Windows yasaklı karakterler, UTF-8 boundary, Türkçe);
  url scheme (safe http/https + unsafe javascript/file/smb/data/
  vbscript/ms-msdt/zoom-us).

### Changed (post-review hardening)
- Reserved device adı kontrolü **ilk** nokta öncesi stem üzerinde
  (`split_name`'in son-nokta mantığı `CON.tar.gz` gibi çoklu uzantılı
  adları kaçırıyordu)
- Trailing dot/space sondan kırpılır (`CON.` / `CON ` Windows'ta `CON`
  açar, bypass engellendi)
- NTFS ADS karakteri `:` ve diğer Windows yasaklı `<>"/\\|?*`
  karakterleri filter listesinde
- Ek reserved device adları: CONIN$, CONOUT$, CLOCK$

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
