# HekaDrop

macOS için Google Quick Share (eski adıyla Nearby Share) alıcısı. Android cihazlardan
Mac'e dosya, URL ve metin aktarımını; paywall'sız, bulutsuz ve E2E şifreli bir şekilde
sağlar.

Menü çubuğu arka plan uygulaması — Dock'ta görünmez. Tüm trafik yerel Wi-Fi üzerinden
P-256 ECDH + AES-256-CBC + HMAC-SHA256 ile şifrelenir.

## Özellikler

- Menü çubuğu ikonu (`⇄`) — Dock'tan bağımsız, LSUIElement arka plan modu
- mDNS/Bonjour keşfi: `_FC9F5ED42C8A._tcp.local.`
- Google Quick Share protokolü:
  - UKEY2 handshake (P-256 ECDH + HKDF-SHA256)
  - AES-256-CBC + HMAC-SHA256 secure messages
  - PayloadTransfer chunk reassembly
- Aktarım öncesi kullanıcı onayı: PIN + dosya listesi gösteren native dialog
- Büyük dosyalar için **disk stream** (bellekte toplamaz)
- URL paylaşımı → `open` ile tarayıcıda açar
- Metin paylaşımı → sistem panosuna kopyalar
- macOS Notification Center bildirimleri

## Gereksinimler

- macOS 11+
- Rust 1.90+ (stabil)
- protoc (Protobuf derleyicisi) — `brew install protobuf`

## Derleme

```bash
cargo build --release
./scripts/bundle.sh      # HekaDrop.app paketler
```

Çalıştırma:

```bash
open target/release/HekaDrop.app
# veya terminalden:
cargo run
```

## Kullanım

1. HekaDrop'u aç → menü çubuğunda `⇄` simgesi çıkar.
2. Android'de **Paylaş → Quick Share** → Mac'iniz listede görünür.
3. Dosya gönderince Mac'te PIN'li onay dialog'u açılır.
4. **Kabul et** → dosya `~/Downloads/` altına iner + bildirim gelir.
5. **Reddet** → aktarım iptal, karşı taraf haberdar edilir.

## Mimari

```
src/
├── main.rs         — tokio background runtime + tao event loop + tray menü
├── config.rs       — mDNS service type, instance name, EndpointInfo
├── mdns.rs         — Bonjour servis yayını
├── server.rs       — TCP accept loop
├── frame.rs        — 4-byte BE length-prefix framing
├── ukey2.rs        — P-256 handshake + HKDF key derivation + PIN
├── crypto.rs       — HKDF, AES-256-CBC, HMAC-SHA256, PIN türetme
├── secure.rs       — DeviceToDeviceMessage şifre/deşifre + sequence
├── payload.rs      — chunk reassembly + FILE stream + BYTES buffer
├── connection.rs   — state machine + sharing frame akışı
├── ui.rs           — osascript dialog + Notification Center
└── error.rs
```

## Güvenlik Notları

- Her oturum için yeni ephemeral P-256 anahtar çifti
- Commitment doğrulama: `SHA512(ClientFinished) == cipher_commitment`
- MITM koruması: 4-haneli PIN her iki cihazda aynı olmalı (auth string)
- Trafik UKEY2 sonrası tamamen şifreli + HMAC imzalı
- Dosyalar doğrudan yerel ağ üzerinden gelir, hiçbir sunucuya uğramaz

## Teşekkürler

Protokol referansı için:
- [grishka/NearDrop](https://github.com/grishka/NearDrop) — Swift ile yazılmış Quick Share receiver
- [teaishealthy/pyquickshare](https://github.com/teaishealthy/pyquickshare) — Python implementasyonu
- Google'ın resmi [Nearby Connections SDK](https://developers.google.com/nearby/connections/overview) proto tanımları

## Bilinen Sınırlamalar

- Yalnız **alıcı** (receiver) — Mac → Android yönünde gönderim yok
- Wi-Fi LAN üzerinden, Wi-Fi Direct fallback'i desteklenmez
- macOS'a özel (Linux/Windows için ayrı UI katmanı gerekir)
- Code signing yok (Gatekeeper ilk açılışta "Geliştirici doğrulanamadı" uyarısı verebilir — sağ tık → Aç)

## Lisans

Apache-2.0 — `.proto` tanımları Google'ın lisansıyla aynı.
