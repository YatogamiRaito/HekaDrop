# HekaDrop

HekaDrop — Google Quick Share protokolünü Rust ile konuşan açık kaynak, ücretsiz dosya paylaşım aracı.

[![Release](https://img.shields.io/github/v/release/YatogamiRaito/HekaDrop?display_name=tag&sort=semver)](https://github.com/YatogamiRaito/HekaDrop/releases)
[![CI](https://github.com/YatogamiRaito/HekaDrop/actions/workflows/ci.yml/badge.svg)](https://github.com/YatogamiRaito/HekaDrop/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/YatogamiRaito/HekaDrop/branch/main/graph/badge.svg)](https://codecov.io/gh/YatogamiRaito/HekaDrop)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)

Google'ın kapalı kaynak **QuickDrop** aboneliğine özgür, reklamsız ve tamamen yerel
çalışan bir alternatif. Android, ChromeOS ve diğer Quick Share uyumlu cihazlarla
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

- **Quick Share uyumlu** — UKEY2 handshake, AES-256-CBC + HMAC-SHA256, P-256 ECDH.
- **mDNS/Bonjour keşfi** (`_FC9F5ED42C8A._tcp.local.`) — aynı ağdaki cihazları görür ve görünür olur.
- **Çift yönlü**: hem alıcı hem gönderici. Dosya, URL, metin parçaları.
- **Trusted devices (whitelist)** — güvendiğiniz cihazlar her seferinde PIN sormadan otomatik kabul edilir
  ve **rate limit kurallarının dışında tutulur**.
- **Rate limiter** — varsayılan 60 saniye içinde aynı IP'den en fazla 10 bağlantı kabul edilir;
  whitelist'teki cihazlar bu throttle'dan muaftır.
- **SHA-256 integrity** — alınan her dosyanın hash'i aktarım sonunda doğrulanır.
- **Disk-stream kaydetme** — gigabayt boyutlu dosyalar bellek şişirmeden yazılır.
- **Aktarım iptali** — gönderilen ya da alınan aktarım istenildiği zaman durdurulabilir.
- **Log rotation** — günlük dosya + en fazla 3 gün geriye saklama + tekil dosya 10 MB'a ulaştığında
  truncate (disk şişme koruması).
- **İstatistik + Tanı sekmesi** — toplam byte, dosya sayısı, cihaz bazında kırılım, canlı servis durumu.
- **Otomatik güncelleme kontrolü** — GitHub Releases API'si ile yeni sürüm uyarısı (arka planda, opsiyonel).
- **macOS native UI** — menü çubuğu ikonu, tab'lı pencere (Ana / Geçmiş / Ayarlar / Tanı), native onay dialog'u.
- **Universal2 binary** — tek `.app` hem Intel hem Apple Silicon'da çalışır.

## Ekran görüntüleri

<!-- screenshots: docs/ -->
<!-- Henüz eklenmedi. `docs/` altına eklenince bu blok güncellenecek. -->

## Kurulum

### Homebrew (önerilen — yakında)

```bash
brew install --cask yatogamiraito/tap/hekadrop
```

> Tap (`yatogamiraito/homebrew-tap`) henüz yayında değil — **coming soon**.
> O zamana kadar DMG veya kaynaktan kurulum yolunu kullanın.

### DMG (GitHub Releases)

1. [Releases](https://github.com/YatogamiRaito/HekaDrop/releases) sayfasından en güncel
   `HekaDrop-<version>.dmg` dosyasını indirin.
2. DMG'yi açın ve **HekaDrop.app**'i **Applications** klasörüne sürükleyin.
3. İlk açılışta macOS Gatekeeper uyarısı gelirse: **Ayarlar → Gizlilik & Güvenlik → Yine de Aç**.

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
- **AES-256-CBC + HMAC-SHA256** — UKEY2 sonrası tüm D2D mesajları imzalı ve şifreli.
- **Replay koruması** — sequence counter; sunucu ve istemci tarafında çift yönlü doğrulama.
- **SHA-256 integrity** — alınan her dosya için beklenen hash ile karşılaştırma.
- **Rate limiter** — spam/DoS'a karşı IP başına pencereli sayaç.
  Trusted device listesindeki cihazlar bu sayacın dışında tutulur (muafiyet); bu sayede
  sizin ev/iş cihazlarınız throttle edilmeden hızla bağlanır.
- **Yerel ağ** — hiçbir paket dış sunucuya uğramaz; hesap/token/telemetri yoktur.
- **Config dosyası** — ayarlar JSON olarak `~/Library/Application Support/HekaDrop/config.json`
  altında saklanır (keychain entegrasyonu yol haritasında).
- **Log disiplini** — günlük rotasyon, en fazla 3 gün saklama ve tek dosya 10 MB üst sınırı;
  log dosyaları diskte şişemez.

## Platform durumu

| Platform | Alıcı | Gönderici | UI  | Notlar |
|----------|:-----:|:---------:|:---:|--------|
| macOS    | ✅    | ✅        | ✅  | Universal2 (Intel + Apple Silicon), DMG + Homebrew cask |
| Linux    | 🚧    | 🚧        | ⏳  | Çekirdek protokol hazır; tepsi/UI katmanı planlanıyor (zbus + webkit2gtk) |
| Windows  | ⏳    | ⏳        | ⏳  | Yol haritasında (tray-icon + webview2, MSIX paketleme) |
| Android / iOS | —  | —      | —   | Karşı taraf cihaz olarak kullanılır; native istemci geliştirilmeyecek |

Lejant: ✅ tamam · 🚧 geliştirme aşamasında · ⏳ planlı

## Yol haritası

- **0.2.0** — clipboard senkronizasyonu, İngilizce arayüz (i18n altyapısı), klasör drag-drop, SHA-256 integrity UI göstergesi
- **0.3.0** — Linux UI (zbus tray + webkit2gtk penceresi, systemd user service)
- **0.4.0** — Windows UI (tray-icon + webview2, MSIX paket, winget manifest)
- **0.5.0+** — partial transfer resume, keychain entegrasyonu, otomatik klasör indirme kuralları

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

**HekaDrop** is a free, open-source Rust client for Google's Quick Share (Nearby Share)
protocol. It speaks UKEY2 + AES-256-CBC + HMAC-SHA256, performs mDNS discovery on
`_FC9F5ED42C8A._tcp.local.`, and acts as both receiver and sender — a drop-in
local-network alternative to Google's closed-source QuickDrop. The macOS build ships
as a Universal2 `.app` with a menu bar UI; Linux and Windows ports are on the roadmap.
Security features include ephemeral P-256 ECDH, 4-digit PIN MITM protection, SHA-256
file integrity, replay-safe sequence counters, a rate limiter (trusted devices bypass
it), and disciplined log rotation (daily + max 3 files + 10 MB cap).
