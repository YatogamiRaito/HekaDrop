# HekaDrop

Google Quick Share (eski adıyla Nearby Share) protokolünün **Rust ile yazılmış cross-platform**
istemcisi. Android, macOS, Linux ve Windows arasında dosya, URL ve metin aktarımı;
paywall'sız, bulutsuz ve E2E şifreli.

Mimari tek tek crate'lere ayrıştırılmıştır; platforma özgü katman (tray, pencere, dialog)
değiştirilerek çekirdek protokol (UKEY2, secure message, payload) yeniden kullanılır.

## Platform Desteği

| Platform | Durum | Notlar |
|---|---|---|
| macOS    | ✅ Referans implementasyon | menü çubuğu, native dialog, `.app` paketleme |
| Linux    | 🚧 Planlanıyor | systemd user service, libappindicator/zbus menü |
| Windows  | 🚧 Planlanıyor | tray-icon + webview2, MSIX paketleme |
| Android/iOS | ❌ Odak dışı | hedef cihazlar olarak kullanılır (karşı taraf) |

## Özellikler

### Protokol (tüm platformlarda ortak)
- **mDNS/Bonjour keşfi** — `_FC9F5ED42C8A._tcp.local.`
- **UKEY2 handshake** — P-256 ECDH + HKDF-SHA256 + 4 haneli PIN
- **AES-256-CBC + HMAC-SHA256** secure messages (sequence + replay koruması)
- **PayloadTransfer** chunk reassembly (BYTES + FILE streaming)
- **Çoklu dosya / URL / text** aktarımı
- **İki yönlü**: alıcı + gönderici

### Kullanıcı arayüzü
- Arka plan servisi (Dock/taskbar'da görünmez, yalnız sistem tepsisinde)
- Native onay dialog'u (PIN + dosya listesi + kabul/ret)
- Canlı aktarım ilerleme barı
- Drag-and-drop gönderim (pencereye dosya sürükle)
- Son aktarımlar geçmişi
- Aktarım iptal edilebilir

### Operasyonel
- Disk-stream kaydetme (büyük dosya ≠ bellek sorunu)
- JSON config: `~/.../HekaDrop/config.json`
- Log dosyası rotation (günlük, max 3 gün, 10 MB üst sınır)
- 14 unit test (UKEY2 + secure roundtrip + PIN determinism)

## Gereksinimler (Geliştirici)

- Rust 1.90+ (stabil)
- `protoc` (Protobuf derleyicisi)
- macOS için: `iconutil` (Xcode CLT), `hdiutil` (dahili)
- İsteğe bağlı: `pngquant` — ikon optimize

```bash
# macOS
brew install protobuf pngquant
```

## Kurulum

### Homebrew (önerilen — yakında)

```bash
brew install --cask YatogamiRaito/hekadrop/hekadrop
```

Tap kurulana kadar [Releases](https://github.com/YatogamiRaito/HekaDrop/releases)
sayfasından DMG'yi indirip Applications'a sürükleyin.

### Kaynaktan derleme

```bash
brew install protobuf pngquant        # protoc + icon optimize

cargo test                            # 14 test
make universal                        # Intel + ARM64 universal2 binary
make bundle                           # HekaDrop.app
make dmg                              # HekaDrop-<version>.dmg

make install                          # /Applications'a kur
make install-service                  # oturum açılışında otomatik başlat
```

## Kullanım

1. HekaDrop'u başlat → sistem tepsisinde `⇄` simgesi çıkar.
2. **Alma:** Android'den *Paylaş → Quick Share* → cihazı seç.
3. **Gönderme:** tepsi menüsünde **Dosya gönder…** ya da pencereye dosya sürükle.
4. Her aktarım PIN'li dialog ile onaylanır.
5. Alınan dosyalar `~/Downloads/` altına iner.

## Mimari

```
src/
├── main.rs         — platform UI orkestrasyonu (tray + window + event loop)
├── server.rs       — TCP accept
├── connection.rs   — receiver state machine
├── sender.rs       — sender state machine
├── discovery.rs    — mDNS browse (outbound keşif)
├── mdns.rs         — mDNS advertise (inbound görünürlük)
├── ukey2.rs        — client + server handshake
├── secure.rs       — AES-CBC + HMAC D2D mesajları
├── payload.rs      — chunk reassembly + file stream
├── crypto.rs       — HKDF, HMAC, AES, PIN, D2D salt
├── frame.rs        — 4-byte BE length-prefix
├── config.rs       — service type, instance name, endpoint info
├── state.rs        — global state (settings + progress + history + flags)
├── settings.rs     — JSON config persistence
├── ui.rs           — platform UI helper (dialog, notify, clipboard)
└── error.rs
```

Platform-özgü modüller (`main.rs`, `ui.rs`) değiştirilerek çekirdek protokol katmanı
(ukey2, secure, payload, connection, sender, discovery, mdns, crypto, frame) yeniden
kullanılır. Linux ve Windows portları bu stratejiyi izler.

## Güvenlik

- Her oturum için yeni ephemeral P-256 anahtar çifti
- `SHA512(ClientFinished) == cipher_commitment` doğrulama
- MITM koruması: 4 haneli PIN iki cihazda aynı olmalıdır
- UKEY2 sonrası tüm trafik AES-256-CBC + HMAC-SHA256 imzalı
- Sequence number tabanlı replay koruması
- Dosyalar doğrudan yerel ağ üzerinden; hiçbir sunucuya uğramaz

## Yol Haritası

- [x] Alıcı (Android → macOS)
- [x] Gönderici (macOS → Android)
- [x] Çoklu dosya / URL / text
- [x] Stream kaydetme
- [x] Aktarım iptali
- [x] Menü çubuğu + basit pencere
- [x] `.app` + DMG + launchd agent
- [ ] Linux portu (zbus menu, systemd user service)
- [ ] Windows portu (tray + webview2, MSIX)
- [ ] Trusted devices (whitelist, PIN'siz otomatik kabul)
- [ ] SHA-256 integrity check
- [ ] Partial transfer resume
- [ ] Homebrew / winget / Flatpak paketleri
- [ ] GitHub Actions CI (otomatik release)
- [ ] i18n (şu an TR + EN planlı)

## Teşekkürler

Protokol referansı için:
- [grishka/NearDrop](https://github.com/grishka/NearDrop) — Swift/macOS receiver
- [teaishealthy/pyquickshare](https://github.com/teaishealthy/pyquickshare) — Python/Linux
- Google'ın resmi [Nearby Connections SDK](https://developers.google.com/nearby/connections/overview) proto tanımları

## Lisans

Apache-2.0 — `.proto` tanımları Google'ın lisansıyla aynı.
