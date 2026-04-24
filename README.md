# HekaDrop

HekaDrop — Google Quick Share (eski adıyla Nearby Share) protokolünü Rust ile konuşan
açık kaynak, ücretsiz dosya/metin paylaşım aracı.

[![Release](https://img.shields.io/github/v/release/YatogamiRaito/HekaDrop?display_name=tag&sort=semver)](https://github.com/YatogamiRaito/HekaDrop/releases)
[![CI](https://github.com/YatogamiRaito/HekaDrop/actions/workflows/ci.yml/badge.svg)](https://github.com/YatogamiRaito/HekaDrop/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/YatogamiRaito/HekaDrop/branch/main/graph/badge.svg)](https://codecov.io/gh/YatogamiRaito/HekaDrop)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

Google'ın kapalı kaynak **Quick Share** istemcisine özgür, reklamsız ve tamamen yerel
çalışan bir alternatif. Android 6+ (Quick Share etkin), ChromeOS ve diğer uyumlu cihazlarla
doğrudan — bulut yok, hesap yok, tracker yok.

---

## İçindekiler

- [Özellikler](#özellikler)
- [Ekran görüntüleri](#ekran-görüntüleri)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Mimari](#mimari)
- [Güvenlik](#güvenlik)
- [Platform durumu](#platform-durumu)
- [Yol haritası](#yol-haritası)
- [Geliştirme](#geliştirme)
- [Katkıda bulunma](#katkıda-bulunma)
- [Lisans](#lisans)
- [Teşekkürler](#teşekkürler)
- [English summary](#english-summary)

---

## Özellikler

- **Quick Share uyumlu** — UKEY2 handshake (downgrade-safe), AES-256-CBC + HMAC-SHA256, P-256 ECDH.
- **mDNS/Bonjour keşfi** (`_FC9F5ED42C8A._tcp.local.`) — aynı ağdaki cihazları görür ve görünür olur.
- **Çift yönlü**: hem alıcı hem gönderici. Dosya, düz metin ve URL. URL'ler wire'da
  `TextMetadata.Type::URL` etiketiyle gönderilir; her iki tarafta da aynı `http(s)://`
  allow-list'i uygulanır — gönderirken `javascript:`, `file:`, `data:`, özel protocol
  handler'lar otomatik düz metne dönüşür, alıcı tarafta `is_safe_url_scheme` ile
  tekrar süzülür (defense in depth). Güvenli URL'ler alıcıda varsayılan tarayıcıda
  açılır, güvensizleri panoya düşer. Preview `text_title` sadece `scheme://host` —
  token'lı URL'ler payload geçmişinde kalıcı bırakmaz.
- **Klasör drag-drop** — pencereye sürüklenen dizinler özyinelemeli olarak dosyalara açılır.
- **Trusted devices (whitelist)** — güvendiğiniz cihazlar her seferinde PIN sormadan otomatik kabul edilir
  ve **rate limit kurallarının dışında tutulur**. v0.6.0'dan itibaren **kriptografik hash-first**
  trust kararı (spoofing'e karşı sertleştirilmiş, bkz. [design 017](docs/design/017-trusted-id-hardening.md)).
- **Rate limiter** — varsayılan 60 saniye içinde aynı IP'den en fazla 10 bağlantı kabul edilir;
  whitelist'teki cihazlar bu throttle'dan muaftır. Ayrıca 32 eşzamanlı bağlantı semaphore'u
  farklı IP'lerden flood'a karşı kaynak guard'ı sağlar.
- **SHA-256 digest** — her alınan dosya için yerel hash hesaplanır ve Geçmiş sekmesinde gösterilir.
  Transport bütünlüğü her D2D mesajı başına HMAC-SHA256 ile sağlanır (replay + tamper koruması).
- **Disk-stream kaydetme** — gigabayt boyutlu dosyalar bellek şişirmeden yazılır.
- **Aktarım iptali** — gönderilen ya da alınan aktarım istenildiği zaman durdurulabilir (per-transfer
  CancellationToken; pencere kapanmaz, kısmi dosyalar diskten temizlenir).
- **Log rotation** — günlük dosya + en fazla 3 gün saklama + 10 MB/dosya truncate cap (disk şişme koruması).
- **Gizlilik toggle'ları** (v0.6.0) — LAN mDNS yayını, log seviyesi, istatistik kaydı ve güncelleme kontrolü
  Ayarlar → Gizlilik sekmesinden tek tıkla kapatılabilir. Receive-only mod desteklenir (`advertise=false`).
- **Symlink TOCTOU koruması** — disk'e yazım hedefi symlink ise transfer reddedilir.
- **İstatistik + Tanı sekmesi** — toplam byte, dosya sayısı, cihaz bazında kırılım, canlı servis durumu.
- **Yeni sürüm kontrolü** — GitHub Releases API'si kullanıcı arayüzündeki **Güncelleme kontrol et**
  aksiyonu ile manuel olarak sorgulanır. Yeni sürüm bulunursa kullanıcıya bilgi verilir;
  **otomatik indirme/kurulum yoktur** — yükseltme işlemi manuel yapılır. `HEKADROP_NO_UPDATE_CHECK`
  env veya Ayarlar → Gizlilik toggle'ı ile devre dışı bırakılabilir.
- **macOS native UI** — menü çubuğu ikonu, tab'lı pencere (Ana / Geçmiş / Ayarlar / Tanı), native onay dialog'u.
- **Universal2 binary** — tek `.app` hem Intel hem Apple Silicon'da çalışır.
- **i18n** — Türkçe (varsayılan) + İngilizce arayüz.

## Ekran görüntüleri

<!-- screenshots: docs/ -->
<!-- Henüz eklenmedi. `docs/` altına eklenince bu blok güncellenecek. -->

## Kurulum

### Homebrew (macOS)

```bash
brew install --cask yatogamiraito/tap/hekadrop
```

Tap (`yatogamiraito/homebrew-tap`) v0.6.0 ile public yayına girdi. Cask her yeni release'te güncellenir.

### Releases (zip / deb / exe)

| Platform | Asset | Kurulum |
|---|---|---|
| macOS | `HekaDrop-x.y.z.dmg` | DMG'i aç, `HekaDrop.app`'i `Applications`'a sürükle. İlk açılışta Gatekeeper uyarısı için: **Ayarlar → Gizlilik & Güvenlik → Yine de Aç** (imzasız/notarize edilmemiş) |
| Ubuntu/Debian | `HekaDrop-x.y.z.deb` | `sudo apt install ./HekaDrop-x.y.z.deb` |
| Windows | `HekaDrop-x.y.z.exe` | İndir → çalıştır (unsigned; Defender "Run anyway") |

[Releases sayfası](https://github.com/YatogamiRaito/HekaDrop/releases/latest) — çekilmiş tag için artifact + checksum.

### Scoop (Windows)

Scoop manifest'i repoda: [`scoop/hekadrop.json`](scoop/hekadrop.json). Bucket public olmadığı
için şimdilik manuel kurulum: [Releases](https://github.com/YatogamiRaito/HekaDrop/releases/latest)
sayfasından `.exe`'yi indirip çalıştırın. Bucket public olduğunda bu bölüm `scoop bucket add`
komutuyla güncellenir.

### Kaynaktan derleme

```bash
# Bağımlılıklar
brew install protobuf pngquant

# Derle, test et, kur
git clone https://github.com/YatogamiRaito/HekaDrop.git
cd HekaDrop
make test                  # cargo test
make universal             # Intel + ARM64 universal2 binary
make install               # /Applications'a kopyalar
make install-service       # oturum açılışında otomatik başlat (launchd)
```

Gereksinimler: Rust 1.90+, `protoc`, Xcode CLT (macOS için `iconutil`).

### Linux (AppImage / deb / kaynak)

#### Kaynaktan

```bash
# Sistem bağımlılıkları (Debian/Ubuntu)
sudo apt install protobuf-compiler libwebkit2gtk-4.1-dev libxdo-dev \
                 libsoup-3.0-dev libgtk-3-dev \
                 zenity wl-clipboard  # kdialog ve xclip da kabul edilir

# Derle ve kur
git clone https://github.com/YatogamiRaito/HekaDrop.git
cd HekaDrop
make test
make install-linux          # ~/.local/bin + ~/.local/share/applications (user)
# veya
sudo make install-linux-system  # /usr/local/bin + /usr/share/applications (system)
```

Runtime paketleri: `zenity` (dialog'lar için şart — yoksa `kdialog` fallback), `wl-clipboard`
veya `xclip`/`xsel` (gelen URL/metni panoya kopyalamak için), `notify-osd` veya herhangi
bir libnotify implementasyonu (bildirimler + aksiyon butonları).

#### .deb paketi

```bash
make deb                    # cargo-deb ile target/debian/hekadrop_<ver>_amd64.deb üretir
sudo apt install ./target/debian/hekadrop_*.deb
```

`.deb` paketleri v0.6.0'dan itibaren [GitHub Releases](https://github.com/YatogamiRaito/HekaDrop/releases/latest)
sayfasında da yayınlanır.

#### UFW / firewall notu

```bash
sudo ufw allow 47893/tcp    # HekaDrop TCP sabit portu
sudo ufw allow 5353/udp     # mDNS / Bonjour
```

TCP port varsayılan olarak **47893**'tür; farklı bir port kullanmak için `HEKADROP_PORT`
ortam değişkenini ayarlayın.

#### Otomatik başlatma

Tepsi (tray) menüsünden **"Başlangıçta aç"**'ı işaretleyin — `~/.config/systemd/user/`
altına bir user unit yükler ve `systemctl --user enable` ile oturum açılışında başlatır.

#### Pencere kapatma davranışı

Pencerenin `X` düğmesine basınca uygulama arkaplanda çalışmaya devam eder; tamamen
kapatmak için tepsi menüsünden **"Çıkış"**'ı kullanın. GNOME'da tepsi ikonu varsayılan
olarak görünmeyebilir — [AppIndicator Support](https://extensions.gnome.org/extension/615/appindicator-support/)
GNOME uzantısını yükleyin.

## Kullanım

1. **HekaDrop**'u başlatın → menü çubuğunda `⇄` simgesi belirir.
2. **Alma:** Android telefonda *Paylaş → Quick Share* → listede HekaDrop cihaz adını seçin.
   Ekranda beliren 4 haneli PIN'i karşılaştırın, **Kabul et**'e basın.
3. **Gönderme:** menü çubuğundan **Dosya gönder…** ya da pencereye dosya sürükleyin →
   hedef cihazı listeden seçin.
4. **Ayarlar sekmesi:** cihaz adı, indirme klasörü, otomatik güncelleme kontrolü,
   tepsi davranışı.
5. **Trusted devices (Ayarlar içinde):** güvendiğiniz cihazı tek sefer kabul ettikten sonra
   **"güven listesine ekle"** seçerseniz bir daha PIN sormaz ve rate limit kurallarına tabi olmaz.
6. **Geçmiş sekmesi:** son aktarımlar, başarı/hata durumu, dosya boyutu.
7. **Tanı sekmesi:** servis çalışıyor mu, mDNS kaydı canlı mı, ağ arayüzleri, toplam
   kullanım istatistikleri, log dosyası yolu.

Alınan dosyalar varsayılan olarak `~/Downloads/` altına iner; Ayarlar'dan değiştirilebilir.

## Mimari

HekaDrop iki katmana ayrılmıştır: **platformdan bağımsız çekirdek protokol** ve
**platforma özgü UI**. Linux ve Windows portları yalnızca ikinci katmanı değiştirerek
yazılacaktır.

```
src/
├── main.rs         ─ platform UI orkestrasyonu (tao event loop + wry WebView + tray-icon)
├── ui.rs           ─ platform UI helper (dialog, notify, clipboard)
├── platform.rs    ─ platform abstraction (paths, open, clipboard, device name)
│
├── server.rs       ─ TCP accept + rate limiter
├── connection.rs   ─ receiver state machine
├── sender.rs       ─ sender state machine
├── discovery.rs    ─ mDNS browse (outbound keşif)
├── mdns.rs         ─ mDNS advertise (inbound görünürlük)
│
├── ukey2.rs        ─ UKEY2 client + server handshake
├── secure.rs       ─ AES-256-CBC + HMAC-SHA256 D2D mesajları
├── payload.rs      ─ chunk reassembly + dosya stream
├── crypto.rs       ─ HKDF, HMAC, AES, PIN, D2D salt
├── frame.rs        ─ 4-byte BE length-prefix wire format
│
├── config.rs       ─ servis tipi, instance adı, endpoint info
├── settings.rs     ─ JSON config persistence (+ migration)
├── state.rs        ─ global state (settings + progress + history + flags)
├── stats.rs        ─ toplam byte / dosya / cihaz istatistikleri
└── error.rs
```

- **Runtime:** Tokio multi-thread (rt-multi-thread + net + io-util + fs + time).
- **UI:** `tao` event loop ana thread'de; `wry` WebView HTML/CSS/JS UI sayfasını sunar.
- **Tepsi ikonu:** `tray-icon` crate'i ile sistem tepsisinde.
- **Protokol:** Prost üretimli protobuf tipleri (`proto/` → `build.rs`).

## Güvenlik

- **Ephemeral P-256 ECDH** — her oturum için yeni anahtar çifti, perfect forward secrecy.
- **MITM koruması** — iki cihazda eşleşen 4 haneli PIN + `SHA512(ClientFinished) == cipher_commitment`.
- **UKEY2 downgrade koruması** — cipher/curve/version downgrade teşebbüsleri handshake'te reddedilir
  (regresyon: `tests/ukey2_downgrade.rs`, cipher_commitment flood guard).
- **AES-256-CBC + HMAC-SHA256** — UKEY2 sonrası tüm D2D mesajları imzalı ve şifreli.
- **Replay koruması** — sequence counter; sunucu ve istemci tarafında çift yönlü doğrulama.
- **SHA-256 digest + HMAC** — alınan her dosyanın yerel hash'i hesaplanıp Geçmiş sekmesinde gösterilir;
  aktarım bütünlüğü per-SecureMessage HMAC-SHA256 ile sağlanır (Quick Share wire format'ı transmit hash
  içermediği için "expected vs actual" karşılaştırması yoktur).
- **Rate limiter** — spam/DoS'a karşı IP başına pencereli sayaç (60 sn / 10 bağlantı). Ek olarak
  32 eşzamanlı bağlantı semaphore'u farklı IP'lerden flood'a karşı kaynak guard'ı sağlar.
  Trusted device'lar rate limit'ten muaftır; v0.6.0'dan itibaren trust kararı **kriptografik
  hash-first**'tür ([design 017](docs/design/017-trusted-id-hardening.md)).
- **Yerel ağ** — hiçbir paket dış sunucuya uğramaz; hesap/token/telemetri yoktur.
  Gizlilik toggle'ları (Ayarlar → Gizlilik) mDNS yayınını, update check'i ve istatistik yazımını
  kapatmanıza izin verir.
- **Symlink TOCTOU koruması** — disk'e yazım hedefi symlink ise transfer reddedilir.
- **Malformed peer koruması** — negatif `FileMetadata.size` değerleri sıfıra sabitlenir ve
  1 TiB üzerindeki dosyalar için aktarım iptal edilir; `cipher_commitment` flood guard
  (8 üstü / 9+ element reddedilir).
- **Config dosyası** — ayarlar JSON olarak `~/Library/Application Support/HekaDrop/config.json`
  altında atomic write ile saklanır (tmp file + rename). Gizli dosyalar (örn. `identity.key`)
  ek olarak `0o600` POSIX izni ile yazılır; keychain entegrasyonu yol haritasında.
- **Log disiplini** — günlük rotasyon, en fazla 3 gün saklama ve tek dosya 10 MB üst sınırı;
  log dosyaları diskte şişemez.

## Platform durumu

| Platform | Alıcı | Gönderici | UI  | Notlar |
|----------|:-----:|:---------:|:---:|--------|
| macOS    | ✅    | ✅        | ✅  | Universal2 (Intel + Apple Silicon), DMG + Homebrew cask |
| Linux    | ✅    | ✅        | ✅  | GTK3 + WebKit2GTK + AppIndicator tray; zenity/kdialog dialog; systemd user service; Ubuntu/Debian .deb |
| Windows  | ✅    | ✅        | ✅  | tray-icon + WebView2 (wry); MessageBoxW + PowerShell Forms dialog; Registry `Run` autostart; `.exe` artifact (MSIX/winget yol haritasında) |
| Android / iOS | —  | —      | —   | Karşı taraf cihaz olarak kullanılır; native istemci geliştirilmeyecek |

Lejant: ✅ tamam · 🚧 geliştirme aşamasında · ⏳ planlı

## Yol haritası

**Shipped** (bkz. [CHANGELOG](CHANGELOG.md)):

- **0.2.0–0.3.0** — i18n altyapısı, klasör drag-drop, Linux UI (GTK3 + WebKit2GTK + AppIndicator tray,
  systemd user service) ✅
- **0.4.0** — Windows UI (tray-icon + WebView2, `.exe` artifact) ✅
- **0.5.x** — Trusted device kimlik modeli, atomic config, `FileMetadata.size` guard, metin gönderimi ✅
- **0.6.0** — Kriptografik hash-first trust ([design 017](docs/design/017-trusted-id-hardening.md)),
  per-transfer CancellationToken, Privacy toggles (advertise / log_level / keep_stats /
  disable_update_check), Windows PDB sidecar debug symbols ✅

**Planlı:**

- macOS dSYM + Linux dwp release debug symbols (v0.6.1).
- Partial transfer resume (Quick Share protokolü buna resmi destek vermediği için receiver-side
  best-effort olacak; tasarım araştırması açık).
- macOS Apple Developer ID signing + notarization.
- Windows Authenticode code-signing + MSIX/winget manifest.
- Linux AppImage.
- Keychain/Secret Service entegrasyonu (identity.key için).

## Geliştirme

```bash
make run                                           # debug modda çalıştır
make test                                          # tüm unit + integration testler
cargo clippy --all-targets -- -D warnings          # strict lint
cargo fmt                                          # formatla
make universal                                     # universal2 release binary
```

Daha fazla hedef için: `make help`.

## Katkıda bulunma

Hata raporları, PR'lar ve öneriler memnuniyetle karşılanır. Lütfen önce
[CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun — commit mesajı konvansiyonu,
lint/test checklist'i ve test kapsamı beklentisi orada açıklanıyor.

## Lisans

[MIT](LICENSE) — © 2026 sourvice.com.

Protobuf tanımları (`proto/`) Google'ın Nearby Connections SDK'sından alındı ve
Apache-2.0 lisansı ile uyumludur.

## Teşekkürler

Protokolün tersine mühendislik çalışmasına ve referans implementasyonlara teşekkürler:

- [grishka/NearDrop](https://github.com/grishka/NearDrop) — Swift/macOS alıcı; protokol keşfinin büyük kısmı
- [teaishealthy/pyquickshare](https://github.com/teaishealthy/pyquickshare) — Python/Linux referansı
- Google Nearby Share ekibi — [Nearby Connections SDK](https://developers.google.com/nearby/connections/overview) proto tanımları

## English summary

**HekaDrop** is a free, open-source Rust client for Google's **Quick Share** (formerly
Nearby Share) protocol. It speaks UKEY2 + AES-256-CBC + HMAC-SHA256 over P-256 ECDH,
discovers peers via mDNS on `_FC9F5ED42C8A._tcp.local.`, and works as both receiver
and sender (files, plain text, and URLs). URLs are tagged with
`TextMetadata.Type::URL` on the wire and auto-opened in the default browser on the
receiver after `http(s)://` allow-list validation; unsafe schemes fall through to
the clipboard. The same allow-list runs on the sender too (defense in depth).

**Distributions:** macOS Universal2 `.dmg` + Homebrew cask, Linux `.deb` + systemd
user service + GTK3/WebKit2GTK tray UI, Windows `.exe` + WebView2 + Registry Run
autostart (MSIX/winget on the roadmap). Folder drag-drop is supported; large files
stream to disk without memory spikes.

**Security:** ephemeral P-256 ECDH (PFS), 4-digit PIN with `SHA512(ClientFinished) ==
cipher_commitment` MITM check, UKEY2 downgrade rejection (cipher/curve/version),
per-SecureMessage HMAC-SHA256 + sequence-counter replay defense, per-IP rate limiter
(60 s / 10 conns — trusted devices bypass), 32-connection concurrency semaphore for
cross-IP flood resistance, cryptographic hash-first trusted-device model
([design 017](docs/design/017-trusted-id-hardening.md)), symlink-TOCTOU and
`FileMetadata.size` guards, atomic config writes with `0o600` mode on secret files
(e.g. `identity.key`), and disciplined log rotation
(daily + max 3 files + 10 MB cap). No cloud, no account, no telemetry; privacy toggles
for mDNS advertisement, update check, log level, and stats writing live in Settings →
Privacy. A per-file SHA-256 digest is computed locally and surfaced in History (no
expected-hash comparison is transmitted — Quick Share wire format does not include
one).
