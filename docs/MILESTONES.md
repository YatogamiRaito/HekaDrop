# HekaDrop Milestones — GitHub Projects Referansı

Bu doküman `docs/ROADMAP.md`'ten türetilmiş, GitHub Projects/Milestones'a doğrudan taşınabilir biçimde, sürüm bazlı kesin teslimat listelerini içerir. Her sürüm için: tema, hedef tarih, kabul ölçütleri ve oluşturulacak issue tohumları.

**Gözlem:** Bu belge makine-okunabilir değil (YAML/JSON değil) — GitHub CLI ile toplu issue yaratmak için `scripts/seed-milestones.sh` ayrı bir işlem olacak (v0.7.0 sonrası).

---

## Aktif Milestone'lar

### v0.7.0 — Foundation (Hedef: 2026-06-15)

**Tema:** Workspace refactor + dürüstlük geçişi + Issue #17 art işlemi + URL payload kararı

**Kabul ölçütleri:**
- [ ] `cargo build --workspace --all-features` yeşil
- [ ] `cargo test --workspace` yeşil, coverage ≥ %70
- [ ] `hekadrop-core` crate'i `cargo publish --dry-run` başarılı
- [ ] `docs/rfcs/0001-workspace-refactor.md` Accepted
- [ ] `docs/rfcs/0002-url-payload.md` Accepted (A veya B kararı)
- [ ] `docs/features-audit.md` yayında; tüm 🔴 critical gap'ler kapandı
- [ ] `docs/security/threat-model.md` yayında
- [ ] `fuzz/` scaffold çalışır; `cargo +nightly fuzz build` başarılı
- [ ] `docs/MILESTONES.md` + `docs/rfcs/README.md` yayında (✅ v0.7.0 scope'ta bu PR)
- [ ] Branch `feature/v0.7-foundation` → `main` merge edildi

**Oluşturulacak issue'lar:**
1. `[rfc] RFC-0001 review döngüsü` — workspace migration tartışması
2. `[rfc] RFC-0002 review döngüsü` — URL payload A/B
3. `[refactor] Step 1 — workspace Cargo.toml kurulumu`
4. `[refactor] Step 2 — hekadrop-proto crate ayrıştırma`
5. `[refactor] Step 3-N — core/net/app modül göçleri` (RFC sonrası parçalanır)
6. `[docs] features-audit 🔴 gap'leri için takip`
7. `[security] threat-model bulguları → izlenebilir issue'lar`
8. `[ci] fuzz.yml on-demand workflow validation`

**Labels (yeni):** `rfc`, `rfc:review`, `refactor:workspace`, `area:core`, `area:proto`, `area:net`, `area:app`, `area:cli`, `q1-foundation`

---

### v0.8.0 — Protokol Sağlamlaştırma (Hedef: 2026-07-31)

**Tema:** Chunk-level HMAC + transfer resume + folder streaming

**Kabul ölçütleri:**
- [ ] `docs/rfcs/0003-chunk-hmac.md` Accepted
- [ ] `docs/rfcs/0004-transfer-resume.md` Accepted
- [ ] `docs/rfcs/0005-folder-payload.md` Accepted
- [ ] `docs/protocol/resume.md` — wire format spec (RFC formatında, alan uzunlukları byte-level)
- [ ] Chunk-level HMAC `hekadrop-core::secure` içinde; eski fullfile HMAC geri uyumluluğu `capabilities` negotiation arkasında
- [ ] Resume protokol: `~/.hekadrop/partial/` dizini, 7 gün TTL, cleanup job
- [ ] Folder streaming: tar-like iç format, dosya başı ayrı SHA-256 + chunk-HMAC
- [ ] Integration test: 1 GiB dosya network drop → resume → tamamlandı
- [ ] Benchmark: chunk-HMAC overhead < %2 throughput etkisi

**Oluşturulacak issue'lar:**
1. `[rfc] RFC-0003 chunk-HMAC protokolü`
2. `[rfc] RFC-0004 transfer resume protokolü`
3. `[rfc] RFC-0005 folder payload`
4. `[feature] chunk-HMAC implementation`
5. `[feature] resume implementation (sender side)`
6. `[feature] resume implementation (receiver side)`
7. `[feature] folder streaming`
8. `[test] 1 GiB resume integration test`
9. `[bench] chunk-HMAC throughput benchmark`

**Labels:** `q1-foundation`, `protocol:breaking-opt-in`, `area:core`

---

## Q2 Milestone'ları

### v0.9.0 — Fuzzing Olgunluk + Audit Hazırlık (Hedef: 2026-09-30)

**Tema:** Fuzzing altyapısı 10 harness'a çıkar; crypto audit vendor seçilir; NLnet başvurusu gönderilir

**Kabul ölçütleri:**
- [ ] 10 fuzz harness aktif: ukey2_handshake_init, ukey2_handshake_finish, frame_decode_full, frame_decode_partial, payload_header, payload_chunk, secure_decrypt, mdns_txt_parse, protobuf_wireshare_frame, resume_hint_parse
- [ ] Her harness 168 saat crash-free
- [ ] OSS-Fuzz başvurusu gönderildi (cevap Q3'te gelebilir)
- [ ] `cargo-mutants` CI adımı; en az %50 mutation kill rate
- [ ] proptest property-based testler: UKEY2 state machine, payload reassembly, rate limiter
- [ ] `docs/security/audit-scope.md` yayında
- [ ] Audit vendor imzalandı; kickoff 2026-12 için hazır
- [ ] NLnet Privacy & Trust Enhancing Technologies başvurusu gönderildi
- [ ] Sovereign Tech Fund başvuru taslağı hazır

**Oluşturulacak issue'lar:**
1. `[fuzz] ukey2_handshake_finish harness`
2. `[fuzz] 6 ek harness`
3. `[ci] oss-fuzz integration PR`
4. `[test] cargo-mutants CI adımı`
5. `[test] proptest state machines`
6. `[security] audit scope doc`
7. `[grant] NLnet başvurusu`
8. `[grant] STF başvurusu`

**Labels:** `q2-hardening`, `area:security`, `area:fuzzing`, `grant`

---

### v0.10.0 — CLI + Headless Daemon (Hedef: 2026-10-31)

**Tema:** `hekadrop` CLI binary, croc-benzeri tek statik binary, systemd/launchd daemon unit dosyaları

**Kabul ölçütleri:**
- [ ] `crates/hekadrop-cli` dolmuş; 3 platformda smoke test pass
- [ ] Komutlar: `send`, `receive`, `list-peers`, `trust <add|remove|list>`, `doctor`, `version`, `check-update`, `gui`, `daemon`
- [ ] `--json` output modu her komut için
- [ ] stdin pipe → send (örn. `cat file.pdf | hekadrop send --filename file.pdf`)
- [ ] Static musl binary ~4-6 MiB Linux x86_64
- [ ] `docs/deploy/systemd.md`, `docs/deploy/launchd.md`, `docs/deploy/windows-service.md`
- [ ] man pages: `hekadrop(1)`, `hekadrop-send(1)`, `hekadrop-receive(1)`, `hekadrop-trust(1)`
- [ ] Real-device interop CI matrix: Pixel 7/Android 14-16, Samsung Galaxy One UI 6-7, ChromeOS, Windows 11 Quick Share app, nightly
- [ ] `hekadrop.dev` site lansmanı (stealth, private beta bilgisi)
- [ ] 50 kişilik private beta grubu aktif

**Oluşturulacak issue'lar:**
1. `[cli] komut iskelet çatısı`
2. `[cli] send komutu`
3. `[cli] receive/daemon modu`
4. `[cli] JSON output`
5. `[cli] man pages`
6. `[deploy] systemd/launchd/windows-service örnekleri`
7. `[ci] real-device interop matrix self-hosted runner`
8. `[site] hekadrop.dev stealth launch`
9. `[community] private beta davetiyesi sistemi`

**Labels:** `q2-hardening`, `area:cli`, `area:ops`, `area:site`

---

## Q3 Milestone'ları

### v0.11.0 — Windows Signing + MSIX (Hedef: 2026-12-31)

**Tema:** Azure Trusted Signing + MSIX paketi + Winget/Scoop manifest hazırlığı (submission YOK, v1.0.0'da)

**Kabul ölçütleri:**
- [ ] Azure Trusted Signing hesabı açık ve CI'ye secret bağlı
- [ ] Her release `.exe` ve `.msix` otomatik Authenticode imzalı
- [ ] `Package.appxmanifest` yazılı: identity, capabilities (`internetClientServer`, `privateNetworkClientServer`), dependencies
- [ ] WebView2 bootstrapper entegre
- [ ] `.msi` alternatif (WiX Toolset v4) kurumsal deployment için
- [ ] Temiz uninstaller: registry + AppData + startup entry silme
- [ ] Windows Service opsiyonu (hekadrop-daemon)
- [ ] Winget manifest `manifests/h/HekaDrop/HekaDrop/0.11.0/*.yaml` — hazır, submission yok
- [ ] Scoop manifest `bucket/hekadrop.json` — hazır, submission yok

**Oluşturulacak issue'lar:**
1. `[ops] Azure Trusted Signing onboarding`
2. `[build] MSIX paketleme pipeline`
3. `[build] MSI alternatif (WiX)`
4. `[win] WebView2 bootstrapper`
5. `[win] Windows Service modu`
6. `[win] uninstaller hardening`
7. `[dist] Winget manifest hazırlığı`
8. `[dist] Scoop manifest hazırlığı`

**Labels:** `q3-windows`, `platform:windows`, `area:build`, `area:dist`

---

### v0.12.0 — Windows Auto-Update + Polish (Hedef: 2027-01-31)

**Tema:** Windows kendi auto-updater'ı + Fluent Design + SmartScreen reputation

**Kabul ölçütleri:**
- [ ] Ed25519 signed update manifest
- [ ] Update server: GitHub Releases API + signature verification
- [ ] Rollback: başarısız update → previous version
- [ ] Delta updates araştırması dokümante (bsdiff/xdelta3)
- [ ] Windows 11 Mica effect, rounded corners, accent color
- [ ] Dark mode registry listener
- [ ] Jumplist + toast notification actions + taskbar progress
- [ ] Klavye kısayolları: Ctrl+V, Ctrl+Shift+S, Ctrl+,, F1
- [ ] SmartScreen "clean" statüsü (≥ 1000 indirme reputation eşiği hedefi)
- [ ] Windows 10 v1903+ minimum policy belirlendi

**Labels:** `q3-windows`, `platform:windows`, `area:updater`, `area:ui`

---

## Q4 Milestone'ları

### v0.13.0 — macOS Notarize + Sparkle 2 (Hedef: 2027-03-31)

**Tema:** Developer ID signing + notarization + Sparkle 2 EdDSA updater

**Kabul ölçütleri:**
- [ ] Apple Developer Program aktif ($99/yıl)
- [ ] Developer ID Application sertifikası CI'da
- [ ] `xcrun notarytool` pipeline; stapling çalışıyor
- [ ] Sparkle 2 entegre; Appcast `https://hekadrop.dev/appcast.xml`
- [ ] Ed25519 signing key offline HSM'de
- [ ] Channels: stable / beta (kullanıcı seçebilir)
- [ ] Delta updates Sparkle üzerinden
- [ ] Entitlements minimum (Network, LAN)
- [ ] `LSMinimumSystemVersion` ve Privacy Manifest (`PrivacyInfo.xcprivacy`) doğru
- [ ] Universal2 doğrulandı
- [ ] LaunchAgent login item toggle ayarlardan

**Labels:** `q4-macos`, `platform:macos`, `area:updater`, `area:signing`

---

### v0.14.0 — Share Extensions (Hedef: 2027-04-30)

**Tema:** Finder Share Extension + Safari Share Extension + Quick Look plugin + Services menü

**Kabul ölçütleri:**
- [ ] Finder right-click → Share → HekaDrop çalışır
- [ ] Safari Share sheet → HekaDrop çalışır
- [ ] macOS Services menü entry sistem genelinde
- [ ] Shortcuts action: "Send file to phone"
- [ ] QR code fallback (peer yoksa, NearDrop 2.2.0 paritesi ama varsayılan değil)
- [ ] Menu-bar only mode toggle
- [ ] Resmi Homebrew Cask PR dosyası hazır (submission v1.0.0'da)
- [ ] VoiceOver test geçti

**Labels:** `q4-macos`, `platform:macos`, `area:extensions`, `a11y`

---

## Q5 Milestone'ları

### v0.15.0 — LocalSend v2 Receive (Hedef: 2027-06-30)

**Tema:** Dual-protokol receiver'ın alıcı yarısı — LocalSend v2 spec implementation

**Kabul ölçütleri:**
- [ ] `crates/hekadrop-core/src/localsend/` modülü
- [ ] UDP multicast `224.0.0.167:53317` announce + listen
- [ ] HTTPS self-signed cert server
- [ ] Endpoint'ler: `/api/localsend/v2/prepare-upload`, `/upload`, `/cancel`, `/register`, `/prepare-download`, `/download`
- [ ] Fingerprint SHA-256 hesabı + TOFU trust
- [ ] PIN auth flow
- [ ] Unified `Peer` domain tipi: `PeerProtocol::QuickShare | PeerProtocol::LocalSend`
- [ ] LocalSend client'tan dosya alınabildi (integration test)
- [ ] RFC 0010 `docs/rfcs/0010-dual-protocol.md` Accepted
- [ ] Audit bulguları entegrasyonu (Q4 sonunda geldiyse)

**Labels:** `q5-dual-protocol`, `protocol:localsend`, `area:core`

---

### v0.16.0 — Dual-Receiver UX (Hedef: 2027-07-31)

**Tema:** Send tarafı dual-protocol + unified peer picker + web receiver

**Kabul ölçütleri:**
- [ ] Peer picker QS + LocalSend peer'larını protokol rozetiyle gösterir
- [ ] Dosya gönderimi: peer tipine göre doğru protokol
- [ ] LocalSend web receiver fallback (`http://host:53317/` browser UI)
- [ ] İlk-çalıştırma wizard: "Telefonda hangi app var?" rehberi
- [ ] Trusted onboarding: LocalSend fingerprint confirm akışı
- [ ] Magic Wormhole prototip (opsiyonel, v0.20.0+)

**Labels:** `q5-dual-protocol`, `area:ui`, `area:ux`

---

## Q6 Milestone'ları

### v0.17.0 — Docker + NAS (Hedef: 2027-09-30)

**Kabul ölçütleri:**
- [ ] `ghcr.io/.../hekadrop` multi-arch (amd64, arm64, arm/v7)
- [ ] Base: `distroless/cc-debian12`, ~5 MiB + binary
- [ ] Volume: `/config`, `/downloads`
- [ ] Env: `HEKADROP_DEVICE_NAME`, `HEKADROP_AUTO_ACCEPT_TRUSTED`, `HEKADROP_DOWNLOAD_DIR`
- [ ] Health endpoint: `http://localhost:9090/health`
- [ ] `docker-compose.yml` örnek (host network)
- [ ] Synology SPK, Unraid XML, TrueNAS SCALE Helm chart — hepsi submit-ready
- [ ] Cosign signed manifest
- [ ] Trivy container scan: 0 high-severity CVE
- [ ] Rootless mode destekli

**Labels:** `q6-ecosystem`, `area:docker`, `area:nas`

---

### v0.18.0 — Home Assistant + Web Admin (Hedef: 2027-10-31)

**Kabul ölçütleri:**
- [ ] `homeassistant/custom_components/hekadrop/` integration
- [ ] Entities: `sensor.hekadrop_last_received`, `sensor.hekadrop_active_transfers`
- [ ] Services: `hekadrop.send_file`, `hekadrop.notify_peer`
- [ ] Events: `hekadrop_file_received` automation trigger
- [ ] HACS submission dosyaları hazır (submission v1.0.0'da)
- [ ] `/admin` web UI (auth + CSRF)
- [ ] `/metrics` Prometheus endpoint
- [ ] Grafana dashboard JSON `docs/deploy/grafana/`
- [ ] 2 automation örneği dokümante

**Labels:** `q6-ecosystem`, `area:home-assistant`, `area:web-admin`, `area:metrics`

---

## Q7 Milestone'ları

### v0.19.0 — BLE Advertising (Hedef: 2027-12-31)

**Kabul ölçütleri:**
- [ ] Linux: `bluer` backend
- [ ] macOS: CoreBluetooth bridge
- [ ] Windows: `windows-rs` Bluetooth.Advertisement
- [ ] Google QS BLE spec uyumlu
- [ ] Battery budget: ≤ %3 drain/saat (ölçüm test raporu)
- [ ] `docs/protocol/transport-stack.md` yayında
- [ ] MAC randomization privacy

**Labels:** `q7-transport`, `area:ble`, `platform:all`

---

### v0.20.0 — Wi-Fi Direct Fallback + Hotspot (Hedef: 2028-01-31)

**Kabul ölçütleri:**
- [ ] Linux `wpa_supplicant` P2P API
- [ ] macOS Multipeer Connectivity (yüksek seviye fallback)
- [ ] Windows Wi-Fi Direct API (COM)
- [ ] Fallback flow: LAN → BLE → Wi-Fi Direct
- [ ] Hotspot mode: HekaDrop AP açabilir veya peer AP'ye bağlanabilir
- [ ] Airport senaryosu integration test geçti (iki farklı SSID'deki cihaz)
- [ ] Wi-Fi Aware (iOS 26 + Linux NAN) prototip — opsiyonel, v1.1.0 için

**Labels:** `q7-transport`, `area:wifi-direct`, `platform:all`

---

## Q8 Milestone'ları

### v0.99.0-rc.1 — Feature Freeze (Hedef: 2028-02-29)

**Kabul ölçütleri:**
- [ ] Yeni feature yok (sadece bug fix + polish)
- [ ] Translation vendor/Crowdin çalışır durumda
- [ ] 15 dilde i18n coverage ≥ %90
- [ ] Tüm hata mesajları i18n kapsamında
- [ ] Accessibility audit: VoiceOver, NVDA, Orca

### v0.99.0-rc.2 — Localization Complete (Hedef: 2028-03-15)

**Kabul ölçütleri:**
- [ ] 15 dilde çeviri %100
- [ ] Installer dialog strings i18n
- [ ] Notification strings i18n
- [ ] README 15 dilde
- [ ] Site 5+ dilde

### v0.99.0-rc.3 — Audit Fixes (Hedef: 2028-04-01)

**Kabul ölçütleri:**
- [ ] Audit final report public: `docs/security/audit-2028.pdf`
- [ ] Tüm high-severity bulgular kapalı
- [ ] Medium-severity ≤ 3
- [ ] Reproducible build doğrulandı (3 ortam, bit-identical)
- [ ] Performance benchmark: 1 GiB @ 1 Gbps LAN ≤ 15 saniye

### v1.0.0 — Public Launch (Hedef: 2028-04-24)

**Kabul ölçütleri:**
- [ ] Tüm paket yöneticilerine eş zamanlı submission (Homebrew Cask, Winget, Scoop, Flathub, Snap, AUR bin+source, Nixpkgs, Debian, Fedora, openSUSE)
- [ ] HN Tuesday 08:00 ET submission hazır
- [ ] Press kit hazır: `hekadrop.dev/press`
- [ ] Launch blog post yayında
- [ ] Discord/Matrix public açık, moderator rotası aktif
- [ ] Bug bounty programı yayında
- [ ] GitHub Sponsors + OpenCollective aktif

**Launch-day issue'ları:**
1. `[launch] HN submission`
2. `[launch] Lobsters + ProductHunt + Reddit multi-post`
3. `[launch] Verge + Ars + LWN pitch embargo`
4. `[launch] Homebrew Cask PR (homebrew-cask)`
5. `[launch] Winget PR (winget-pkgs)`
6. `[launch] Scoop PR`
7. `[launch] Flathub manifest`
8. `[launch] Snap Store snapcraft upload`
9. `[launch] AUR bin + source paketleri`
10. `[launch] Nixpkgs PR`
11. `[launch] Debian/Fedora/openSUSE başvuruları`
12. `[launch] HACS submission`
13. `[launch] Moderator rotası aktif`
14. `[launch] Bug bounty programı go-live`

**Labels:** `q8-launch`, `blocker:v1.0.0`

---

## Label Taksonomisi

Bu labeller GitHub'da `.github/labels.yml` veya `github-label-sync` ile yönetilir (v0.7.0 sonrası).

### Çeyrek
- `q1-foundation`, `q2-hardening`, `q3-windows`, `q4-macos`, `q5-dual-protocol`, `q6-ecosystem`, `q7-transport`, `q8-launch`

### Alan
- `area:core`, `area:proto`, `area:net`, `area:app`, `area:cli`
- `area:ui`, `area:ux`, `area:a11y`
- `area:build`, `area:signing`, `area:updater`, `area:ci`
- `area:security`, `area:fuzzing`, `area:crypto`
- `area:docker`, `area:nas`, `area:home-assistant`, `area:metrics`, `area:web-admin`
- `area:ble`, `area:wifi-direct`, `area:mdns`
- `area:i18n`, `area:docs`, `area:site`

### Platform
- `platform:macos`, `platform:linux`, `platform:windows`, `platform:all`

### Protokol
- `protocol:quickshare`, `protocol:localsend`, `protocol:wormhole`, `protocol:breaking-opt-in`

### Durum/tip
- `rfc`, `rfc:review`, `blocker:v1.0.0`, `good-first-issue`, `help-wanted`
- `type:bug`, `type:feature`, `type:refactor`, `type:docs`, `type:test`, `type:security`, `type:grant`

### Öncelik
- `priority:critical`, `priority:high`, `priority:normal`, `priority:low`

---

## GitHub Projects Kurulumu (v0.7.0 PR sonrası)

1. Yeni Projects board: "HekaDrop v1.0.0 Roadmap"
2. Görünümler:
   - **Çeyrekler** (kanban, sütunlar: Q1-Q8 + Done)
   - **Mevcut sürüm** (kanban, Backlog / In Progress / Review / Done)
   - **Tüm RFC'ler** (table, status + target version columns)
   - **Güvenlik** (table, `area:security` filtreli)
3. Her milestone GitHub'a manuel girilir (veya `scripts/seed-milestones.sh` ile toplu).
4. Her milestone'un kabul ölçütleri checklist olarak PR template'inde.

---

## Güncelleme politikası

Bu belge, ROADMAP.md'nin türevidir. Uyuşmazlık durumunda **ROADMAP.md bağlayıcıdır**. Çeyrek sonu retrospektifinde iki belge senkronize edilir; kapanan kabul ölçütleri işaretlenir, yeni issue'lar açılır, tarihler revize edilir.
