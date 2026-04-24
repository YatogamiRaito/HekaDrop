# HekaDrop Feature Audit

**Audit tarihi:** 2026-04-24
**Denetlenen sürüm:** `0.6.0` (Cargo.toml), branch `refactor/pr5-review-fixes`
**Referans README commit:** `c3a844f` (PR #80 "docs(readme): dürüstlük audit")
**Audit kapsamı:** README.md'deki her somut özellik iddiasının kaynak kodla (ve mümkünse testle) eşleştirilmesi.

Bu doküman, README'nin özellik/güvenlik sözü ile gerçek implementasyon arasındaki ilişkinin yaşayan bir haritasıdır. Her release'te güncellenmelidir. README'yi değiştirmez — kodun gerçeğini belgeler. Bulduğu tutarsızlıkları "Gaps" bölümünde sınıflandırır.

---

## Özet Tablosu

| # | Feature | Status | Coverage | Tracking |
|---|---|---|---|---|
| 1 | Quick Share uyumlu (UKEY2, AES-256-CBC + HMAC, P-256 ECDH) | ✅ Implemented | Kapsamlı (handshake + downgrade + HMAC tag length + roundtrip) | — |
| 2 | mDNS/Bonjour keşfi (`_FC9F5ED42C8A._tcp.local.`) | ✅ Implemented | Orta (`mdns_discovery.rs`) | — |
| 3 | Çift yönlü (send + receive) — file, URL, text | ⚠️ Partial (URL ayrı type yok; alıcıda şema ile açılır) | Orta (sender text testi + receiver URL şema testi) | — |
| 4 | Klasör drag-drop | ✅ Implemented | Yok (yalnız main.rs düz kod) | — |
| 5 | Trusted devices (whitelist) | ✅ Implemented | Yüksek (`trust_hijack.rs`, `legacy_ttl.rs`) | — |
| 6 | Rate limiter (60 sn / 10 bağlantı + 32 concurrent semaphore) | ✅ Implemented | Yüksek (`rate_limiter.rs`, `server_rate_limiter.rs`) | — |
| 7 | SHA-256 integrity (per-file digest + per-message HMAC) | ✅ Implemented | Orta (`payload_corrupt.rs`, `hmac_tag_length.rs`) | — |
| 8 | Disk-stream kaydetme | ✅ Implemented | Düşük (`save_non_blocking.rs`) | — |
| 9 | Aktarım iptali (per-transfer CancellationToken) | ✅ Implemented | Orta (`cancel_per_transfer.rs`) | — |
| 10 | Log rotation (daily + 3-day retention + 10 MB cap) | ✅ Implemented | Yok (unit test yok) | — |
| 11 | İstatistik + Tanı sekmesi | ✅ Implemented | Düşük (stats kalıcılığı) | — |
| 12 | Otomatik güncelleme kontrolü (manuel, opsiyonel) | ✅ Implemented | Düşük | — |
| 13 | macOS native UI (menü çubuğu + tab'lı pencere) | ✅ Implemented | Yok (GUI) | — |
| 14 | Universal2 binary | ✅ Implemented | Yok (build script) | — |
| 15 | Platform distribution (Homebrew cask, `.deb`, `.exe`, Scoop manifest) | ✅ Implemented | Yok (CI/release) | — |
| 16 | Internationalization (TR + EN) | ✅ Implemented | Orta (parse_lang + key coverage) | — |
| 17 | Gizlilik toggle'ları (advertise / log_level / keep_stats / disable_update_check) | ✅ Implemented | Yüksek (`privacy_controls.rs`) | — |
| 18 | Symlink TOCTOU koruması | ✅ Implemented | Orta (unit test `payload.rs`) | — |
| 19 | Malformed peer koruması (`FileMetadata.size` clamp + commitment flood guard) | ✅ Implemented | Yüksek (`file_metadata_size_guard.rs`, `ukey2_downgrade.rs`) | — |

---

## Detaylı Özellik Analizi

### Feature: Quick Share uyumlu (UKEY2 + AES-256-CBC + HMAC + P-256 ECDH)
**README claim:** *"Quick Share uyumlu — UKEY2 handshake (downgrade-safe), AES-256-CBC + HMAC-SHA256, P-256 ECDH."*
**Status:** ✅ Implemented
**Code references:**
- `src/ukey2.rs:L40-L155` — client handshake (ClientInit → ServerInit → ClientFinished → HKDF auth/next).
- `src/ukey2.rs:L215-L443` — server handshake + downgrade rejection (`Ukey2HandshakeCipher::P256Sha512` sabit).
- `src/crypto.rs:L1-L248` — HKDF-SHA256, HMAC, AES, PIN türetme, D2D salt.
- `src/secure.rs:L60-L70` — `encryption_scheme = AES_256_CBC`, `signature_scheme = HMAC_SHA256`.
- `src/ukey2.rs:L17-L20` — `p256::ecdh::diffie_hellman` (ephemeral ECDH).
- `src/connection.rs:L108-L140` — server tarafında handshake orkestrasyonu + timeout.

**Test references:**
- `tests/ukey2_handshake.rs` — base case (client ↔ server HKDF sonucu eşleşiyor).
- `tests/ukey2_downgrade.rs` — cipher/curve/version downgrade reddi regression test'i.
- `tests/secure_roundtrip.rs` — AES-256-CBC + HMAC-SHA256 encrypt/decrypt.
- `tests/hmac_tag_length.rs` — HMAC tag length kontrolü.

**Gaps:** Yok.
**Tracking:** —

---

### Feature: mDNS/Bonjour keşfi
**README claim:** *"mDNS/Bonjour keşfi (`_FC9F5ED42C8A._tcp.local.`) — aynı ağdaki cihazları görür ve görünür olur."*
**Status:** ✅ Implemented
**Code references:**
- `src/mdns.rs:L24-L92` — `advertise()` (`ServiceDaemon::new` + `ServiceInfo::new` + `register`).
- `src/discovery.rs:L11-L128` — `ServiceDaemon` ile outbound browse.
- `src/config.rs` — `service_type()` servis tipi üretimi (`_FC9F5ED42C8A._tcp.local.`).
- `Cargo.toml:L20` — `mdns-sd = "0.19"`.

**Test references:**
- `tests/mdns_discovery.rs` — loopback mDNS kayıt + keşif doğrulaması.

**Gaps:** Yok.
**Tracking:** —

---

### Feature: Çift yönlü (send + receive) — file, URL, text
**README claim:** *"Çift yönlü: hem alıcı hem gönderici. Dosya ve metin (URL'ler metin olarak gönderilir; alıcı tarafta URL şeması doğrulanırsa otomatik açılır)."*
**Status:** ⚠️ Partial (URL ayrı bir payload tipi olarak gönderilmiyor; yalnızca TEXT payload tipinin alıcı-tarafındaki şema doğrulaması ile URL davranışı üretiliyor). README zaten bu dürüstlüğü yazıyor — **status işaretleme bu kısıtı yansıtıyor**, README overclaim yapmıyor.
**Code references:**
- **File send:** `src/sender.rs:L140-L370` — `send_file`/`send_files` + PayloadType::File chunk loop.
- **Text send:** `src/sender.rs:L376-L611` — `send_text` (Introduction'da `text_metadata`, payload PayloadType::Bytes olarak).
- **URL send:** `src/sender.rs:L404-L407` — gönderici tarafta `TextKind::Text` sabit (URL olsa bile); ayrı `send_url` / `UrlPayload` **yok**. URL davranışı tamamen alıcı-tarafında doğar.
- **File receive:** `src/connection.rs:L540-L823` + `src/payload.rs:L256-L459` — Introduction → Consent → chunk assembly → disk.
- **Text/URL receive:** `src/connection.rs:L608-L882` — `handle_text_payload` + `is_safe_url_scheme` (`http`/`https` için `platform::open_url`, aksi halde clipboard).

**Prior self-audit verification (conversation memory'den):** Memory kaydı şüpheliydi — "URL send eksik olabilir" diyordu. Grep sonuçları bunu **doğruluyor**: `UrlPayload`, `send_url`, `Url` payload tipi kaynakta yok. Ancak README zaten bu implementasyon detayını doğru ifade ediyor ("URL'ler metin olarak gönderilir"), dolayısıyla "overclaim" değil.
**Test references:**
- `src/connection.rs:L1581-L1631` — `is_safe_url_scheme` unit testleri (http/https evet; javascript/file/smb/data/vbscript/ms-msdt/zoom-us hayır).
- `src/sender.rs:L1003-L1020` — `text_metadata` yapısının payload_id/size/type eşlenmesi regresyonu.
- `tests/secure_roundtrip.rs` — D2D mesaj katmanı.

**Gaps:**
- 🟡 Partial: Sender URL'yi `TextKind::Text` olarak yolluyor (bkz. `sender.rs:L407`); Android alıcıda `TextKind::Url` metadata'sı üretmiyoruz. Bu, Android tarafında "Aç URL" aksiyon butonunun çıkmayıp metin notification'ı çıkmasına yol açabilir. README not düşüyor ama bu ayrım ileride belirginleştirilebilir.

**Tracking:** — (İstenirse yeni issue açılabilir: "sender: URL-benzeri metinler için `TextKind::Url` metadata yolla")

---

### Feature: Klasör drag-drop
**README claim:** *"Klasör drag-drop — pencereye sürüklenen dizinler özyinelemeli olarak dosyalara açılır."*
**Status:** ✅ Implemented
**Code references:**
- `src/main.rs:L15` — `wry::DragDropEvent` import.
- `src/main.rs:L1570-L1620` — klasör recursive enumerate + `symlink_metadata` ile symlink eleme (dizin gibi görünen symlink'ler "symlink" olarak kalır ve elendirilir).

**Test references:** Yok (GUI event path'i; headless test'i yok).
**Gaps:** 🟢 Cosmetic — drag-drop recursion için unit test yok. Kod yolu görsel smoke ile doğrulanıyor.
**Tracking:** —

---

### Feature: Trusted devices (whitelist)
**README claim:** *"Trusted devices (whitelist) — güvendiğiniz cihazlar her seferinde PIN sormadan otomatik kabul edilir ve rate limit kurallarının dışında tutulur. v0.6.0'dan itibaren kriptografik hash-first trust kararı."*
**Status:** ✅ Implemented
**Code references:**
- `src/identity.rs:L1-L329` — cihaz-kalıcı `DeviceIdentity` + `secret_id_hash` türetme (Issue #17).
- `src/connection.rs:L79-L101` — gate'de peer-controlled trust bypass'i yok; rate limit herkese uygulanıyor.
- `src/connection.rs:L513-L530` — `PairedKeyEncryption` alındıktan sonra `forget_most_recent` ile retroaktif trust muafiyeti.
- `src/settings.rs` — `trusted_devices`, `trusted_at_epoch`, TTL alanları.
- `src/main.rs:L622-L700` — UI'dan ekle/sil/clear IPC handler'ları.
- `docs/design/017-trusted-id-hardening.md` — design.

**Test references:**
- `tests/trust_hijack.rs` — peer-controlled ID spoof senaryosu.
- `tests/legacy_ttl.rs` — legacy (hash'siz) trust kaydının TTL'i.

**Gaps:** Yok.
**Tracking:** GitHub Issue #17 (hardening tamamlandı, PR #81 ile kapandı).

---

### Feature: Rate limiter
**README claim:** *"Rate limiter — varsayılan 60 saniye içinde aynı IP'den en fazla 10 bağlantı kabul edilir; whitelist'teki cihazlar bu throttle'dan muaftır. Ayrıca 32 eşzamanlı bağlantı semaphore'u farklı IP'lerden flood'a karşı kaynak guard'ı sağlar."*
**Status:** ✅ Implemented
**Code references:**
- `src/state.rs:L89-L138` — `RateLimiter` (60 sn sliding window, MAX_PER_WINDOW=10, `check_and_record`, `forget_most_recent`).
- `src/server.rs:L22-L84` — `MAX_CONCURRENT_CONNECTIONS = 32` + `Semaphore::try_acquire_owned` (non-blocking reject).
- `src/connection.rs:L94-L101` — gate'de `check_and_record`.

**Test references:**
- `tests/rate_limiter.rs` — unit test.
- `tests/server_rate_limiter.rs` — integration test.
- `src/state.rs:L369-L391` — inline unit test'ler (cap + per-IP isolation).

**Gaps:** Yok. (README "whitelist muaf" diyor — kod hash-first ile muaf bırakıyor, gate'de bypass yok ama retroactive forget var — eşdeğer davranış.)
**Tracking:** —

---

### Feature: SHA-256 integrity
**README claim:** *"SHA-256 digest — her alınan dosya için yerel hash hesaplanır ve Geçmiş sekmesinde gösterilir. Transport bütünlüğü her D2D mesajı başına HMAC-SHA256 ile sağlanır (replay + tamper koruması)."*
**Status:** ✅ Implemented
**Code references:**
- `src/payload.rs:L20` — `sha2::{Digest, Sha256}`.
- `src/payload.rs:L75-L103` — `FileSink.hasher: Sha256` + `sha256: [u8; 32]` in `CompletedPayload::File`.
- `src/payload.rs:L409` — `sink.hasher.update(body)` per-chunk.
- `src/payload.rs:L452-L459` — `finalize()` streaming hash.
- `src/connection.rs:L313-L361` — History item'a `sha256_short` (ilk 16 karakter hex) yazılıyor.
- `src/secure.rs:L66-L67` — `SigScheme::HmacSha256`.

**Test references:**
- `src/payload.rs:L749-L795` — `file_last_chunk_finalizes_and_computes_sha256` (known vector).
- `tests/payload_corrupt.rs` — hatalı payload algılama.
- `tests/hmac_tag_length.rs` — HMAC tag uzunluk kontrolü.

**Gaps:** 🟢 Cosmetic — README "expected vs actual" karşılaştırmasının Quick Share wire format'ında olmadığını zaten açıkça belirtiyor (Güvenlik bölümü L232-234).
**Tracking:** —

---

### Feature: Disk-stream kaydetme
**README claim:** *"Disk-stream kaydetme — gigabayt boyutlu dosyalar bellek şişirmeden yazılır."*
**Status:** ✅ Implemented
**Code references:**
- `src/payload.rs:L23-L104` — `BufWriter<File>` (128 KiB tampon), chunk başına `write_all` (tam dosya bellekte tutulmuyor).
- `src/payload.rs:L368-L410` — `OpenOptions::create(true) + BufWriter + block_in_place_if_multi` (yavaş disk runtime worker'ını tutmasın).

**Test references:**
- `tests/save_non_blocking.rs` — tokio multi-thread runtime içinde I/O'nun worker'ı bloklamadığını doğruluyor.

**Gaps:** 🟢 Cosmetic — GB-ölçekli end-to-end stress test yok (CI süresini fazla uzatır; kod yolu chunk başına tampon olduğu için bellek profilinde sızıntı beklenmez).
**Tracking:** —

---

### Feature: Aktarım iptali (cancel mid-stream)
**README claim:** *"Aktarım iptali — gönderilen ya da alınan aktarım istenildiği zaman durdurulabilir (per-transfer CancellationToken; pencere kapanmaz, kısmi dosyalar diskten temizlenir)."*
**Status:** ✅ Implemented
**Code references:**
- `src/state.rs:L71-L237` — `cancel_root` + `active_transfers: HashMap<String, CancellationToken>` + `TransferGuard` (Drop'ta map'ten siler).
- `src/connection.rs:L41-L46` — her gelen bağlantı için `TransferGuard::new(format!("in:{}", peer))`.
- `src/sender.rs:L177-L178`, `L418-L419` — gönderici tarafta aynı pattern.
- `src/connection.rs:L195-L201, L432-L450` — kullanıcı iptal edince `build_sharing_cancel` + `send_disconnection` + `cleanup_transfer_state` (yarım dosya silimi).
- `src/sender.rs:L424-L436` — connect cancel ile sarmalı.

**Test references:**
- `tests/cancel_per_transfer.rs` — per-transfer iptal izolasyonu (bir transfer'ı iptal etmek diğerini etkilemiyor).

**Gaps:** Yok.
**Tracking:** —

---

### Feature: Log rotation
**README claim:** *"Log rotation — günlük dosya + en fazla 3 gün saklama + 10 MB/dosya truncate cap (disk şişme koruması)."*
**Status:** ✅ Implemented
**Code references:**
- `src/main.rs:L195-L252` — `setup_logging` (`RollingFileAppender::builder().rotation(Rotation::DAILY).max_log_files(3)`).
- `src/main.rs:L218` — `truncate_oversized_logs(&log_dir, 10 * 1024 * 1024)`.
- `src/main.rs:L254-L269` — `cleanup_old_logs` (>3 gün).
- `src/main.rs:L273-...` — `truncate_oversized_logs`.

**Test references:** Yok (dosya sistemi side-effect'li, zamanla flakı olabiliyor).
**Gaps:** 🟢 Cosmetic — truncate + retention için unit test yok. Kod yolu küçük ve self-contained.
**Tracking:** —

---

### Feature: İstatistik + Tanı sekmesi
**README claim:** *"İstatistik + Tanı sekmesi — toplam byte, dosya sayısı, cihaz bazında kırılım, canlı servis durumu."*
**Status:** ✅ Implemented
**Code references:**
- `src/stats.rs:L15-L124` — `DeviceStats`, `Stats`, `per_device_rx`, `per_device_tx` + kalıcılık (`Stats::load`, `Stats::save`).
- `src/main.rs:L1076` — `window.applyStats({...})` ile UI'ya push.
- `resources/window.html:L866-L868, L571-L594` — `#tab-diag`, `.diag-section`, `.diag-row` DOM.

**Test references:** Yok (stats persistence için unit test yok; runtime state).
**Gaps:** 🟢 Cosmetic — Stats serialize/deserialize regression test'i yok.
**Tracking:** —

---

### Feature: Otomatik güncelleme kontrolü
**README claim:** *"Yeni sürüm kontrolü — GitHub Releases API'si kullanıcı arayüzündeki Güncelleme kontrol et aksiyonu ile manuel olarak sorgulanır. Yeni sürüm bulunursa kullanıcıya bilgi verilir; otomatik indirme/kurulum yoktur — yükseltme işlemi manuel yapılır. HEKADROP_NO_UPDATE_CHECK env veya Ayarlar → Gizlilik toggle'ı ile devre dışı bırakılabilir."*
**Status:** ✅ Implemented
**Code references:**
- `src/main.rs:L1414-L1445` — `HEKADROP_NO_UPDATE_CHECK` env + `Settings.disable_update_check` çifte kapı; `https://api.github.com/repos/YatogamiRaito/HekaDrop/releases/latest` GET.
- `src/settings.rs:L266-L291` — `disable_update_check` default `true` (privacy-first).
- `src/main.rs:L1387-` — update-status UI kind'lar.
- `src/i18n.rs:L184, L274-275, L479-480` — strings.

**Test references:**
- `src/settings.rs:L1494-L1578` — `disable_update_check` default + user-override testleri.
- `tests/privacy_controls.rs` — privacy toggle kümesi.

**Gaps:** Yok.
**Tracking:** —

---

### Feature: macOS native UI (menü çubuğu + tab'lı pencere)
**README claim:** *"macOS native UI — menü çubuğu ikonu, tab'lı pencere (Ana / Geçmiş / Ayarlar / Tanı), native onay dialog'u."*
**Status:** ✅ Implemented
**Code references:**
- `src/main.rs:L12-L14` — `tray_icon::TrayIconBuilder`.
- `src/main.rs:L291-L340` — "Dock'ta görünmeme" davranışı + tray menu (Gönder/İptal/Geçmiş/Ayarlar/Çıkış).
- `src/main.rs:L353-L440` — `tao` window + `wry::WebViewBuilder`.
- `resources/window.html:L856-L911` — 4 tab (Ana / Geçmiş / Ayarlar / Tanı) `role="tablist"` ile accessible.
- `src/ui.rs` — native dialog/notify/clipboard wrapper.
- `src/platform.rs` — macOS paths/open/clipboard.

**Test references:** Yok (GUI kodu; unit test kapsamında değil).
**Gaps:** 🟢 Cosmetic — GUI otomasyon testi yok.
**Tracking:** —

---

### Feature: Universal2 binary
**README claim:** *"Universal2 binary — tek `.app` hem Intel hem Apple Silicon'da çalışır."*
**Status:** ✅ Implemented
**Code references:**
- `scripts/build-universal.sh` — `rustup target add x86_64-apple-darwin aarch64-apple-darwin` + iki `cargo build --release` + `lipo -create` birleştirme.
- `scripts/bundle.sh:L18` — universal binary'yi `.app` bundle'ına kopyalıyor.
- `Makefile:L11` — `make universal` hedefi.

**Test references:** CI release workflow (Universal2 artifact'ini üretir).
**Gaps:** Yok.
**Tracking:** —

---

### Feature: Platform distribution (Homebrew, `.deb`, `.exe`, Scoop)
**README claim:** *"Homebrew (macOS), Releases (zip / deb / exe), Scoop (Windows)."*
**Status:** ✅ Implemented (Scoop bucket şimdilik public değil → manifest repoda var, kurulum manuel).
**Code references:**
- `Casks/hekadrop.rb` — Homebrew cask.
- `scoop/hekadrop.json` — Scoop manifest (bucket public olmadığı için `scoop bucket add` yok; README bunu açıkça yazıyor).
- `Cargo.toml:L108-L122` — `[package.metadata.deb]` (`cargo-deb` entegrasyonu).
- `scripts/make-deb.sh`, `scripts/make-dmg.sh`, `scripts/bundle.sh` — paketleme script'leri.
- `Makefile` — `make deb`, `make install-linux`, `make universal`.

**Test references:** CI release workflow (`.dmg`, `.deb`, `.exe` artifact'ları).
**Gaps:** 🟢 Cosmetic — Scoop bucket public değil; README zaten "manuel kurulum" diyor (overclaim yok).
**Tracking:** —

---

### Feature: Internationalization (TR + EN)
**README claim:** *"i18n — Türkçe (varsayılan) + İngilizce arayüz."*
**Status:** ✅ Implemented
**Code references:**
- `src/i18n.rs:L1-L778` — `Lang::{Tr, En}`, `lookup_tr`, `lookup_en`, `t`, `tf` (formatted), `parse_lang`. Fallback: TR'de eksik key EN'e, EN'de eksik key TR'ye düşer.
- `resources/window.html` — `data-i18n="webview.tab.home"` vb. (runtime'da `applyI18n()`).
- `src/main.rs:L901-L935` — tüm webview key'leri I18n bundle'a push.

**Test references:**
- `src/i18n.rs:L552-L565` — `parse_lang` locale parse testleri (`tr`, `tr_TR`, `tr_TR.UTF-8`, `en`, `en_US`, `en-GB`).
- `src/i18n.rs:L715-L750` — key coverage (her webview key'in TR + EN'de bulunması).

**Gaps:** Yok.
**Tracking:** —

---

### Feature: Gizlilik toggle'ları
**README claim:** *"Gizlilik toggle'ları (v0.6.0) — LAN mDNS yayını, log seviyesi, istatistik kaydı ve güncelleme kontrolü Ayarlar → Gizlilik sekmesinden tek tıkla kapatılabilir. Receive-only mod desteklenir (advertise=false)."*
**Status:** ✅ Implemented
**Code references:**
- `src/settings.rs:L266-L291` — `advertise`, `log_level`, `keep_stats`, `disable_update_check` alanları + serde default'ları.
- `src/main.rs:L570, L804-L830, L1022` — IPC parse/push.
- `src/stats.rs:L60-L70` — `keep_stats=false` iken disk'e yazmama.

**Test references:**
- `tests/privacy_controls.rs` — tam toggle matrisi.

**Gaps:** Yok.
**Tracking:** —

---

### Feature: Symlink TOCTOU koruması
**README claim:** *"Symlink TOCTOU koruması — disk'e yazım hedefi symlink ise transfer reddedilir."*
**Status:** ✅ Implemented
**Code references:**
- `src/payload.rs:L341-L365` — `std::fs::symlink_metadata` → `is_symlink()` ise reddet.
- `src/error.rs:L109-L110` — `HekaError::SymlinkRejected` domain error.

**Test references:**
- `src/payload.rs:L690-L712` — `ingest_file_symlink_destination_reddeder` unit testi (gerçek symlink yaratıp reject doğruluyor).

**Gaps:** Yok.
**Tracking:** —

---

### Feature: Malformed peer koruması
**README claim:** *"Malformed peer koruması — negatif `FileMetadata.size` değerleri sıfıra sabitlenir ve 1 TiB üzerindeki dosyalar için aktarım iptal edilir; cipher_commitment flood guard (8 üstü / 9+ element reddedilir)."*
**Status:** ✅ Implemented
**Code references:**
- `src/file_size_guard.rs` — `FileSizeGuard::Accept/Reject` + 1 TiB sınır.
- `src/connection.rs:L566-L594` — Introduction parse + `FileSizeGuard::Reject` dalı.
- `src/ukey2.rs:L261-L306` — ClientInit cipher commitment sayı denetimi.

**Test references:**
- `tests/file_metadata_size_guard.rs` — size clamp + reject testleri.
- `tests/ukey2_downgrade.rs` — commitment flood / downgrade.

**Gaps:** Yok.
**Tracking:** —

---

## Gaps (severity'ye göre)

### 🔴 Critical
— (Yok.) README'de "var" dediği ama kodda bulunmayan hiçbir iddia tespit edilmedi. PR #80 README dürüstlük auditi bu sınıfı zaten temizlemiş görünüyor.

### 🟡 Partial
1. **Sender URL metadata tipi** — `src/sender.rs:L404-L407` URL-benzeri metinleri `TextKind::Text` olarak gönderiyor, `TextKind::Url` değil. Alıcı tarafındaki URL açma davranışını etkilemiyor çünkü HekaDrop alıcısı payload içeriğini şema ile doğruluyor; ancak Android alıcıda "Aç URL" aksiyon butonunun görünüp görünmediği doğrulanmadı (Quick Share spec'ine tam uyum için `TextKind::Url` + `url` alanı doldurulabilir). README "URL'ler metin olarak gönderilir" ifadesi bu kısıtı saklı olarak yansıtıyor — overclaim değil, ama bir improvement fırsatı. **Önerilen aksiyon:** yeni issue açıp Android alıcı davranışını test etmek.

### 🟢 Cosmetic
1. **Klasör drag-drop için unit test yok** — recursion path'i yalnız manuel smoke ile doğrulanıyor.
2. **Log rotation / truncate / retention için unit test yok** — `src/main.rs:L254-L320` civarı; dosya sistemi side-effect'li olduğu için zor ama değerli.
3. **Stats persistence regresyonu yok** — `src/stats.rs` serde roundtrip testi eklenebilir.
4. **GB-ölçekli end-to-end stream stress test yok** — kod zaten chunk-başına disk yazımı yaptığı için yüksek öncelikli değil.
5. **macOS/Windows GUI otomasyon yok** — proje kapsamı dışında.
6. **SHA-256 "expected vs actual" karşılaştırması yok** — README zaten "Quick Share wire format bunu taşımıyor" diyerek saklı; cosmetic değil, **bu bir protokol sınırı** (kapatılamaz).
7. **Scoop bucket public değil** — README açıkça manuel kurulum diyor; release roadmap'inde.

---

## Sonuç

HekaDrop v0.6.0 README'si genel olarak gerçekle **hizalı**. PR #80'in dürüstlük auditi overclaim'leri temizlemiş; bu audit yalnızca bir 🟡 (URL metadata tipi), birkaç 🟢 (test coverage gap'i), sıfır 🔴 tespit etti. Audit'i ileri sürümlerde güncel tutmak için:

- Her yeni feature'ı bu dokümana eklemek (kaynak + test referansı ile).
- Release checklist'ine "feature-audit doc güncellendi mi?" satırı koymak.
- CI'a basit bir grep check eklenebilir: README "Özellikler" madde sayısı ≈ audit feature sayısı (drift alarm).

---

*Doküman sonu.*
