# Changelog

All notable changes to HekaDrop will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Integration test suite (unit + protocol-compliance) kapsayan end-to-end senaryolar
- Strict clippy + coverage + rustdoc CI workflow'ları (`ci.yml`, `coverage.yml`, `docs.yml`)
- `TrustedDevice` struct (name + endpoint ID hash) — legacy string tabanlı whitelist'in yerini alır
- Assembler GC — yarıda kalan (orphan) partial payload'lar için temizlik
- Sender progress otomatik `Idle` sıfırlaması (tamamlanmadan 3 sn sonra)
- Codecov raporu + badge entegrasyonu
- Criterion benchmark iskeleti (`bench.yml`)
- Rustdoc yayın adımı GitHub Pages'e

### Changed
- `Settings` yapısı JSON migration ile geri uyumlu (eski alanlar opsiyonel)
- Rate limiter trusted cihazlar için bypass yolunu erken adımda kestirir (daha az kilit tutma)
- Progress yayınları debounce (UI'ya yansıyan event sayısı azaltıldı)

### Fixed
- Reject sonrası pending destination temizliği (orphan dosyalar geride kalmıyordu)
- `total_bytes=0` sender edge case — boş dosya gönderimi açıkça reddedilir (division-by-zero panic riski kalktı), multi-file `i64` overflow koruması eklendi
- Unknown trusted device isim çakışması (endpoint ID hash ile ayrıştırıldı)
- `FileSink.written` ölü kod temizliği
- mDNS kapatılırken servis kaydı düşürülmeyen nadir race condition

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

[Unreleased]: https://github.com/YatogamiRaito/HekaDrop/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YatogamiRaito/HekaDrop/releases/tag/v0.1.0
