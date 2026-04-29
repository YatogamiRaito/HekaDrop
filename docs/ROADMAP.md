# HekaDrop 24 Aylık Yol Haritası — v1.0.0'a Giden Yol

**Belge tarihi:** 2026-04-24
**Başlangıç sürümü:** v0.6.0 (yayınlanmamış, `refactor/pr5-review-fixes` branch)
**Hedef sürüm:** v1.0.0
**Hedef tarih:** 2028-04-24 (tam 24 ay)
**Strateji özeti:** *"LocalSend iki app ister. HekaDrop telefonda sıfır app ister."* — stock Android Quick Share share sheet'inden erişilebilir, cross-platform, imzalı, dual-protokol (Quick Share + LocalSend v2) Rust receiver. 24 ay boyunca paket yöneticisi yayınları ertelenir; sadece GitHub Releases üzerinden beta kanalı açık kalır.

---

## 0. Yönetici Özeti

### 0.1. Neden 24 Ay Stealth?
- **Mevcut durum:** rquickshare 14 aydır release çıkaramadı (tükendi), NearDrop imzasız ve Eylül 2026 Homebrew zorunluluğuyla ölecek, LocalSend yapısal olarak stock Android share sheet'ine ulaşamaz, Packet sadece Linux.
- **Fırsat penceresi:** "Quick Share'in aktif bakımlı, cross-platform, imzalı, dual-protokol Rust client'i" pozisyonu tamamen boş. Ancak bu pozisyona yarı pişmiş girmek, bir kere imajı bozulan projenin 3.4k yıldız rquickshare gibi sıkışmasıyla sonuçlanır.
- **Çözüm:** İki yıl boyunca sessiz, kalıcı altyapı inşası → v1.0.0'da tüm paket yöneticilerine tek seferde signed + notarize + i18n + dual-protocol + NAS + CLI ile çıkış. Tek atış, maksimum etki.

### 0.2. 1.0.0 Kriterleri (Definition of Done)
v1.0.0, aşağıdakilerin hepsini sağlamadan çıkmaz:
1. **Üç ana platformda imzalı binary** (macOS notarize + Windows Authenticode via Azure Trusted Signing + Linux reproducible build)
2. **Resmi dağıtım kanalları**: Homebrew Cask (ana repo), Winget, Scoop, Flathub, Snap Store, AUR (binary + source), Nixpkgs, Arch official (AUR'dan promosyon), `.deb` (Debian), `.rpm` (Fedora)
3. **Harici crypto audit raporu yayınlanmış** ve bulguları giderilmiş (Trail of Bits, Cure53 veya NLnet sponsored)
4. **Dual-protokol receiver**: Quick Share + LocalSend v2 + (opsiyonel) Magic Wormhole transit
5. **Headless CLI binary + Docker image + Home Assistant integration**
6. **15+ dil i18n kapsaması**
7. **Transfer resume + chunk-level HMAC + folder streaming** çalışıyor
8. **Sparkle 2 (macOS) + WebView2 updater (Windows) + AppImage update** — hepsi signed
9. **Real-device interop CI matrix**: Pixel 7+, Samsung One UI 6+, Windows 11 Quick Share, ChromeOS, Android Auto dahil en az 8 farklı peer
10. **Dokümantasyon sitesi** (`hekadrop.dev`) + **Discord/Matrix topluluğu** + **GitHub Sponsors + OpenCollective**

### 0.3. Yayın Stratejisi
- **Ay 0-23:** GitHub Releases → `beta` channel. İndirme sayfasında **"Pre-release, not for general use"** bandı. Homebrew Cask / Winget / vb. submission **yasak**.
- **Ay 24 (v1.0.0):** Tüm paket yöneticilerine eş zamanlı submission. HN Tuesday launch (Salı 08:00 ET sabah, ML/GitHub trending için optimal). Simültane: Lobsters, ProductHunt, Reddit (r/programming, r/rust, r/linux, r/macapps, r/selfhosted), LWN pitch, Verge/Ars Technica pitch.

---

## 1. Rekabet Konumu (24 Ay İçinde Değişecekler)

| Rakip | Bugün | 12 ay sonra (2027-04) | 24 ay sonra (2028-04) |
|---|---|---|---|
| **LocalSend** | 78.7k ★, son release Şub 2025 | Tienisto dönerse 90k; dönmezse 82k | Potansiyel fork veya yavaş büyüme |
| **rquickshare** | 3.4k ★, tükendi | Ya bakım devralır ya 4k'da donar | 5k civarı veya arşivlenir |
| **NearDrop** | 6.1k ★, imzasız | Eylül 2026 Homebrew zorunluluğu → düşüş | imzalanırsa kalır, yoksa marjinal |
| **Packet** | 903 ★, Linux-only | 2-3k'ya çıkabilir | Linux niche'inde konsolide |
| **HekaDrop** | 0 ★ (stealth) | ~500 ★ (beta adopter'lar) | **Hedef: 15-50k ★ launch hit** |

**Varsayılan piyasa senaryosu:** rquickshare bakımsızlığa yenik düşer, NearDrop macOS-only kalır, Packet Linux niş kalır, LocalSend farklı protokolde kalır. HekaDrop v1.0.0'da "tek aktif bakımlı çapraz-platform Quick Share + LocalSend dual receiver" olarak sahneye çıkar.

---

## 2. Sürüm Takvimi (Ayın Günü Dahil)

| Ay | Çeyrek | Sürüm | Tarih | Tema |
|---|---|---|---|---|
| 1 | Q1 | v0.7.0 | 2026-06-15 | Workspace refactor + README dürüstlük |
| 3 | Q1 | v0.8.0 | 2026-07-31 | Chunk-HMAC + Resume + Folder streaming |
| 5 | Q2 | v0.9.0 | 2026-09-30 | Fuzzing altyapısı + audit hazırlık |
| 6 | Q2 | v0.10.0 | 2026-10-31 | CLI binary + headless daemon |
| 8 | Q3 | v0.11.0 | 2026-12-31 | Azure Trusted Signing + MSIX |
| 9 | Q3 | v0.12.0 | 2027-01-31 | Windows auto-update + polish |
| 11 | Q4 | v0.13.0 | 2027-03-31 | Developer ID + notarize + Sparkle 2 |
| 12 | Q4 | v0.14.0 | 2027-04-30 | Share extensions (Finder/Safari) |
| 14 | Q5 | v0.15.0 | 2027-06-30 | LocalSend v2 receive |
| 15 | Q5 | v0.16.0 | 2027-07-31 | Dual-receiver unified UX |
| 17 | Q6 | v0.17.0 | 2027-09-30 | Docker + Synology/Unraid/TrueNAS |
| 18 | Q6 | v0.18.0 | 2027-10-31 | Home Assistant + web admin |
| 20 | Q7 | v0.19.0 | 2027-12-31 | BLE advertising full stack |
| 21 | Q7 | v0.20.0 | 2028-01-31 | Wi-Fi Direct fallback + hotspot |
| 22 | Q8 | v0.99.0-rc.1 | 2028-02-29 | RC1 — feature freeze |
| 23 | Q8 | v0.99.0-rc.2 | 2028-03-15 | RC2 — localization complete |
| 23 | Q8 | v0.99.0-rc.3 | 2028-04-01 | RC3 — audit fixes integrated |
| 24 | Q8 | **v1.0.0** | **2028-04-24** | **Public launch** 🚀 |

Ara sürümler (v0.x.y patch'ler) gerektiği kadar çıkar. Minor (x) kadansı iki ayda bir, patch (y) haftalık pencereler.

---

## 3. Çeyreklik Derinlik (Q1 → Q8)

Her çeyrek için aşağıdaki bölümler yer alır:
- **Tema & amaç**
- **Teknik deliverable'lar** (kod)
- **Ops/Altyapı deliverable'ları** (CI, sign, release pipeline)
- **Güvenlik deliverable'ları**
- **UX/Polish deliverable'ları**
- **Dokümantasyon & topluluk deliverable'ları**
- **KPI (başarı ölçütleri)**
- **Riskler & azaltmalar**
- **Karar kapısı (go/no-go kriterleri)**

---

## Q1 — "Foundation" (Ay 1-3, 2026-05 → 2026-07)

### Tema & Amaç
README'nin vaat ettiklerini kodun gerçekten yaptığı noktaya çek. Monolitik binary'yi workspace'e böl (core protocol engine'i yeniden kullanılabilir kütüphane yap). Üç kritik protokol zaafiyetini (chunk-HMAC eksikliği, resume yok, Issue #17 trust race) gider. Bundan sonraki her şey bu zemine oturacak.

### Teknik Deliverable'lar

**v0.7.0 — Workspace Refactor (2026-06-15)**
- `Cargo.toml` → workspace; üyeler:
  - `crates/hekadrop-core` (protocol engine: `ukey2`, `crypto`, `secure`, `payload`, `frame`, `connection`, `sender`, `server`, `mdns`, `errors`, `state`)
  - `crates/hekadrop-proto` (generated protobuf + ileri seviye builders)
  - `crates/hekadrop-net` (transport abstractions: TCP, mDNS, ileride BLE/Wi-Fi Direct)
  - `crates/hekadrop-app` (tao/wry UI, tray, settings, platform-specific code)
  - `crates/hekadrop-cli` (henüz iskelet, v0.10.0'da şişecek)
- Protocol engine **reusable library olarak versionlanır**; Cargo semver uyumluluğu v0.1.0'dan başlatılır.
- Dokümantasyon: `crates/hekadrop-core/README.md` ayrı lisans, API docs (`cargo doc`).
- Platform-specific kod `#[cfg(...)]` davranışıyla `hekadrop-app/src/platform/{macos,linux,windows}.rs` altına taşınır.
- `build.rs` → `hekadrop-proto/build.rs` taşınır; app crate'inin build süresi %40+ düşer.

**v0.7.0 devam — README Dürüstlük Geçişi**
- `send_url()` iki şekilde çözümlenir:
  - **Seçenek A (önerilen):** first-class `UrlPayload` tipi implementasyonu; `payload.rs`'de enum variant, `hekadrop-core` public API. CLI `--url` flag.
  - **Seçenek B (fallback):** README'den "URL payload" iddiası kaldırılır, roadmap'e taşınır.
- **Klasör gönderimi netleşir:** `FolderPayload` tipi eklenir (recursive walk + manifest). Boş klasörler, symlink'ler, büyük (>4 GiB) klasörler için açık davranış dokümanı.
- README `Özellikler` tablosu: her madde kod referansıyla eşleşir (audit için `docs/features-audit.md`).
- Screenshots eklenir (placeholder'lar yerine gerçek macOS + Linux + Windows ekran görüntüleri; `docs/screenshots/`).

**v0.8.0 — Protokol Sağlamlaştırma (2026-07-31)**
- ✅ **Chunk-level HMAC** (RFC-0003, `CHUNK_HMAC_V1`): her 512 KiB chunk için ayrı HMAC-SHA256 tag; `secure.rs` refactor. Mid-stream corruption anında tespit, tüm dosyayı beklemek yerine chunk başında kesim.
- ✅ **Transfer resume** (RFC-0004, `RESUME_V1`): protokol mesaj eklentisi `ResumeHint { session_id, file_id, offset, partial_hash }`. Receiver yarım dosyaları `~/.hekadrop/partial/` altında tutar (7 gün TTL, cleanup sweep job'u). Sender `ResumeHint`'i görünce seeker'dan başlar. Geri uyumluluk: capability negotiation. Spec: `docs/protocol/resume.md`. PR-G ile re-enabled (PR #138).
- ✅ **Folder streaming** (RFC-0005, `FOLDER_STREAM_V1`): `HEKABUND` v1 container — header + JSON manifest + per-file body + trailer SHA-256. Disk'te tar oluşturmaz; in-memory streaming. Her dosya yine ayrı SHA-256 + chunk-HMAC + RESUME_V1 ile korunur. Receiver atomic-reject pipeline (staging dir + Drop guard). UI: accept dialog folder summary + completion notification "Klasörü Aç" aksiyonu (Finder/Explorer/xdg-open). Spec: `docs/protocol/folder-payload.md`. PR-A → PR-F.
- **Issue #17 fix**: Trusted device verification UKEY2 sonrasına taşınır. Pre-handshake rate-limit bypass kaldırılır. Test: `tests/trust_race.rs` — name/id spoof senaryosu.
- **Protobuf şema versioning**: `proto/v2/` dizini; geriye uyumluluk için v1 shim.

### Ops/Altyapı Deliverable'ları
- **GitHub Actions matrisi genişletilir:**
  - `macos-14` (arm64) + `macos-13` (x86_64) + `ubuntu-22.04` + `ubuntu-24.04` + `windows-2022` + `windows-11-preview`
  - MSRV CI: 1.90.0 pin'li (`rust-toolchain.toml`)
  - Nightly MSRV-drift kontrol
- **Release pipeline prototipi:** `cargo-dist` veya el yapımı `release.yml`; sadece GitHub Releases'a push (paket yöneticisi submission yok).
- **Reproducible build** araştırması başlatılır; `cargo-vet` + `cargo-auditable` eklenir.
- **Cargo.lock vendor** opsiyonel; supply chain için başlangıç.
- **codecov.io** uyumlu test coverage; %70 floor.

### Güvenlik Deliverable'ları
- `cargo audit` + `cargo-deny` yeşil (GTK3 EOL hariç; bu iş Q4'te GTK4 geçişiyle kapanır).
- **Fuzzing başlangıç**: `cargo-fuzz` kurulumu; ilk hedefler `ukey2::parse_handshake_init`, `frame::decode`, `payload::parse_header`, `secure::decrypt`.
- `docs/security/threat-model.md` yazılır: STRIDE analizi, trust boundaries, attacker model (same-LAN adversary, malicious trusted device, stale trust token).
- Crypto audit için vendor karşılaştırması başlatılır: Trail of Bits, Cure53, NCC Group, Least Authority. NLnet Privacy & Trust Enhancing Technologies başvuru taslağı hazırlanır (son gün: Ekim 2026).

### UX/Polish Deliverable'ları
- Settings sekmesinde **"Diagnostics" alt-tab'ı** zenginleşir: servis durumu, mDNS record live-state, ağ interface'leri, son 10 transfer (anonim ID'lerle), log dosya konumu.
- macOS menu-bar ikonu renk/durum animasyonu (transfer sırasında nabız atar).
- Linux Wayland uyumluluğu kontrol pass'i; `libayatana-appindicator` fallback davranışı test edilir.

### Dokümantasyon & Topluluk
- `docs/` dizini yapılandırılır:
  - `docs/architecture.md` (workspace haritası)
  - `docs/protocol/` (Quick Share spec, bizim eklemelerimiz, resume spec)
  - `docs/security/threat-model.md`
  - `docs/contributing.md` (CONTRIBUTING'den ayrı detay)
- Discord server kurulur (**henüz topluluk daveti yok**, iç kullanım).
- Matrix bridge: `#hekadrop:matrix.org` (Discord'a köprü).

### KPI (Q1 Sonu Başarı Ölçütleri)
- ✅ Workspace refactor merge'de, tüm testler yeşil.
- ✅ `hekadrop-core` crate `cargo publish --dry-run` başarılı (dokümantasyon ve public API hazır).
- ✅ Chunk-HMAC + resume protokol spec yayınlanmış.
- ✅ Issue #17 kapalı, regresyon testi mevcut.
- ✅ Test coverage ≥ %70.
- ✅ Fuzzing 72 saat crash-free.
- ✅ README — kod audit %100 eşleşme.

### Riskler & Azaltmalar (Q1)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| Workspace refactor gizli API kırılımı | Orta | Yüksek | Feature-flag ile kademeli; yeni crate paralelinde legacy code korunur, smoke test'lerde karşılaştırma |
| Resume protokolü Quick Share extra_capabilities'de çakışma | Düşük | Orta | Sadece receiver'da opsiyonel; sender yoksa fallback normal akış |
| Chunk-HMAC geriye uyumsuz | Orta | Yüksek | Version negotiation; eski peer'larla full-file HMAC fallback |

### Karar Kapısı Q1→Q2
- **Go:** Tüm KPI'lar sağlanmış, v0.8.0 release tag'i çıkmış, refactor regresyonları yok.
- **No-go:** Workspace refactor 4 haftayı geçtiyse veya chunk-HMAC protokolünde geriye uyumsuz bug varsa, Q2'nin ilk ayı kapatma sprint'ine ayrılır; Q2 fuzzing/audit deliverable'ları iki hafta kayar.

---

## Q2 — "Hardening" (Ay 4-6, 2026-08 → 2026-10)

### Tema & Amaç
Protokolün doğruluğunu harici doğrulamaya hazırla. Fuzzing altyapısını olgunlaştır, crypto audit vendor seç, NLnet başvurusunu gönder, CLI binary'yi üret (headless deployment'lara kapı açar). Faz 6'daki NAS/Docker/Home Assistant hikayesinin teknik zemini burada atılır.

### Teknik Deliverable'lar

**v0.9.0 — Fuzzing + Audit Hazırlık (2026-09-30)**
- **cargo-fuzz harnesses** 10'a çıkarılır:
  - `fuzz_ukey2_handshake_init`, `fuzz_ukey2_handshake_finish`
  - `fuzz_frame_decode_full`, `fuzz_frame_decode_partial`
  - `fuzz_payload_header`, `fuzz_payload_chunk`
  - `fuzz_secure_decrypt` (random ciphertext + tag)
  - `fuzz_mdns_txt_parse`
  - `fuzz_protobuf_wireshare_frame`
  - `fuzz_resume_hint_parse`
- **Corpora:** gerçek Pixel/Samsung traffic capture'larından türetilmiş; `fuzz/corpus/` altında.
- **oss-fuzz** entegrasyonu başvurusu (Google tarafından 7/24 fuzzing ücretsiz).
- **cargo-mutants** entegrasyonu; dead-code + gereksiz branch tespiti.
- **afl.rs** alternatif fuzzer olarak CI'da haftada bir çalışır.
- **Property-based testing (proptest)** kritik state machines için: UKEY2 state transitions, payload reassembly, rate limiter.

**v0.10.0 — CLI Binary + Headless Daemon (2026-10-31)**
- `crates/hekadrop-cli` şişer:
  - `hekadrop send <file>` — auto-discover peer, PIN prompt, progress bar
  - `hekadrop send <file> --to <device-name>` — direct named target
  - `hekadrop receive` — long-running daemon
  - `hekadrop receive --dir ~/Downloads --accept trusted` — headless modda auto-accept sadece trusted
  - `hekadrop list-peers` — visible peer dump
  - `hekadrop trust add|remove|list`
  - `hekadrop doctor` — ağ teşhisi (croc gibi)
  - `hekadrop version` + `hekadrop check-update` (signed Releases API ile — v0.11.0'da signing)
- **Headless daemon modu**: `hekadrop daemon --config /etc/hekadrop.toml` — systemd unit + launchd plist + Windows service örnek dosyaları `docs/deploy/`
- **`--json` output modu**: her komut için structured output, HA/scripting için.
- Unix philosophy: stdin pipe → send (örn. `cat report.pdf | hekadrop send --filename report.pdf`).
- **Static binary:** `hekadrop-cli` için `cargo build --release --target x86_64-unknown-linux-musl` test edilir; ~4-6 MiB hedef.
- **Tek binary prensibi**: `hekadrop` CLI GUI app'i de başlatabilir (`hekadrop gui`).

### Ops/Altyapı Deliverable'ları
- **Real-device interop CI matrisi** (self-hosted runners):
  - Raspberry Pi 5 + Pixel 7 ADB pair (Android 14, 15, 16 multi-boot)
  - Intel NUC + Samsung Galaxy S24 (One UI 6 + 7)
  - MacBook Air M2 → ChromeOS Flex
  - Windows 11 PC → Android pair (Quick Share Windows app karşılaştırması)
- Nightly interop test'ler; Slack/Discord webhook ile alert.
- **GitHub Actions release pipeline** olgunlaştırılır: `cargo-dist` ile multi-target artifact. Henüz submission YOK, sadece Releases.
- **reproducible-builds.org** uyum kontrol başlatılır (bit-for-bit identical builds).

### Güvenlik Deliverable'ları
- **NLnet başvurusu gönderilir** (son gün Ekim 2026 penceresi). Başvuruda: dual-protokol receiver, audit finansmanı, Wi-Fi Aware prototipi.
- **Trail of Bits / Cure53 vendor seçimi tamamlanır**; paralel olarak OTF (Open Tech Fund) Rapid Response başvurusu.
- Audit scope hazırlanır: `docs/security/audit-scope.md` — UKEY2 implementation, AES-CBC + HMAC, trust store, rate limiter, path sanitization.
- **cargo-vet** denetimi: tüm doğrudan dependency'ler manuel denetlenmiş.
- `SECURITY.md` genişletilir: bug bounty politikası taslağı (henüz aktif değil, v1.0.0'da).
- Fuzzing ile bulunan tüm hatalar `SECURITY-ADVISORIES.md`'e girer (henüz public yok, 90-gün coordinated disclosure sonrası açılır).

### UX/Polish
- **Log rotation hardening**: max 3 gün + 10 MB per file doğrulanır, edge case testleri (saat değişimi, disk full).
- **Diagnostics tab**: CLI `hekadrop doctor` çıktısını GUI'de de göster.
- **Error messages genel geçiş**: teknik jargon → kullanıcıya dönük. Her hata için `hekadrop_core::Error` domain enum'una `user_message()` method.

### Dokümantasyon & Topluluk
- **`hekadrop.dev` site lansmanı**: Astro/Zola statik site. Bölümler:
  - Ana sayfa: "Telefonda app yok" manifesto
  - `/download` (henüz sadece GitHub Releases linki)
  - `/docs` (architecture, protocol spec, security model)
  - `/blog` (ilk post: "Neden HekaDrop?")
  - `/status` (CI + interop matrix live)
- **Blog:** 2026-09'da "HekaDrop Update: Rust-native Quick Share for Everyone" — Hacker News hedefi DEĞİL (erken), sadece SEO ve erken early adopter.
- **Discord** iç kullanım bitti, **private beta Discord** açılır (invite-only, maksimum 50 kişi).
- **CLI man pages** (`hekadrop(1)`, `hekadrop-send(1)`, vb.).

### KPI (Q2 Sonu)
- ✅ 10 fuzz harness, her biri 168 saat crash-free.
- ✅ `hekadrop-cli` 3 platformda çalışır, smoke test pass.
- ✅ Audit vendor imzalandı, kickoff 2026-12'de.
- ✅ NLnet başvurusu gönderildi (sonuç 2027 Q1'de).
- ✅ 50 kişilik private beta grubu aktif, haftada 5+ transfer log.
- ✅ Real-device CI matrix %95+ pass rate.

### Riskler & Azaltmalar (Q2)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| Audit vendor fiyat $50k+ bütçeyi aşar | Yüksek | Yüksek | NLnet (€50k hibe) + GitHub Sponsors + Sovereign Tech Fund paralel başvuru |
| Fuzzing UKEY2'de kritik bug bulur | Düşük-Orta | Orta-Yüksek | v0.9.1 hotfix pipeline hazır; coordinated disclosure 90 gün |
| CLI Windows ConPTY / yarış koşulu | Orta | Düşük | WT/PowerShell 7 üzerinde test; `windows-rs` Console API |
| oss-fuzz başvurusu reddedilir | Düşük | Düşük | Sadece self-hosted fuzzing ile devam |

### Karar Kapısı Q2→Q3
- **Go:** Audit vendor imzalı, fuzz clean, CLI 3 platformda smoke test pass.
- **No-go:** Kritik CVE bulundu ve Q3'e kayma gerekiyorsa, Windows wedge'i Q4'e öteleyip Q3'ü bug fix'e ayır.

---

## Q3 — "Windows Wedge" (Ay 7-9, 2026-11 → 2027-01)

### Tema & Amaç
rquickshare'in 14 aydır kapatamadığı Windows boşluğunu doldur. Azure Trusted Signing + MSIX + Winget/Scoop hazırlığı. **Submission v1.0.0'a kadar YAPILMAZ**, ama binary bugünden imzalı ve paket formatı hazır. SmartScreen reputation inşasına erken başla (ne kadar indirme, o kadar erken "clean" onayı).

### Teknik Deliverable'lar

**v0.11.0 — Azure Trusted Signing + MSIX (2026-12-31)**
- **Azure Trusted Signing account** açılır (Microsoft'un yeni SaaS kod imzalama servisi, ~$10/ay, geleneksel EV cert'ten ucuz ve daha hızlı reputation).
- CI'ya **Authenticode signing adımı**: tüm `.exe` ve `.msix` otomatik imzalanır.
- **MSIX paket formatı**: `Package.appxmanifest` yazılır; identity, capabilities (`internetClientServer`, `privateNetworkClientServer`), dependencies.
- **WebView2 bootstrapper**: Windows 11'de built-in, Windows 10'da installer inject.
- **`.msi` alternatif** (WiX Toolset v4) kurumsal deployment için; ileride Windows Store MSIX ana format.
- **Uninstaller** temiz: tüm registry + `%LOCALAPPDATA%` + `%APPDATA%` + startup entries silinir.
- **Windows Service** (opsiyonel): `hekadrop-daemon` background service olarak kurulabilir.

**v0.12.0 — Windows Auto-Update + Polish (2027-01-31)**
- **Squirrel.Windows benzeri auto-updater**: kendi çözümümüz, WebView2 olmadan. Alternatif: `tauri-updater` backport.
- Update manifest Ed25519 imzalı; update server: GitHub Releases API + signature verification.
- **Rollback**: update başarısız olursa previous version'a döner (`%LOCALAPPDATA%\HekaDrop\versions\`).
- **Delta updates** araştırması (bsdiff/xdelta3); v1.0 için opsiyonel.
- **Windows tray native polish**:
  - Jump list: "Son transfer" + "Geçmiş" + "Ayarlar"
  - Toast notification actions: "Aç", "Klasörü göster", "Devre dışı bırak"
  - Taskbar progress (Windows 11 Mica).
- **Registry `Run` autostart** doğrulanır; UAC prompt'u yok (standart user registry scope).
- **WebView2 runtime check**: yoksa evergreen bootstrapper.
- **Windows 10 support policy**: Windows 10 v1903+ minimum; 2025 sonunda EOL'e girdiği için v1.0.0'da sadece Windows 11 destekli olabilir (karar Q8'de).

### Ops/Altyapı
- **windows-latest CI**'ya signing secret enjeksiyonu (Azure managed identity).
- **SmartScreen reputation farming**: signed `.exe`'yi Microsoft Defender SmartScreen'e submit et, manuel "clean" isteği. İndirme sayıları birikirken reputation yükselir.
- **Windows ARM64 build**: `aarch64-pc-windows-msvc` target; Surface Pro X / ARM Windows için.
- **Winget manifest hazırlığı** (`manifests/h/HekaDrop/HekaDrop/0.12.0/*.yaml`) — submission v1.0.0'da, dosyalar hazır.
- **Scoop manifest** (`bucket/hekadrop.json`) — hazır, yayın kuyruğunda.
- **Chocolatey** nuspec hazırlığı; chocolatey moderation süresi uzun, belki v1.1.0'a erteleriz.

### Güvenlik
- **Audit kickoff** (2026-12 başında) — vendor UKEY2 + crypto modüllerinde çalışmaya başlar.
- **Timing attack review**: AES-CBC padding oracle riski, constant-time HMAC zaten var ama `subtle` audit.
- Windows-specific threat model: Clipboard hijack, tray IPC, WebView2 XSS.

### UX/Polish
- **Windows 11 Fluent Design**: mica effect, rounded corners, accent color.
- **Dark mode**: Windows tema değişimine tepki (registry listen).
- **Klavye kısayolları**: `Ctrl+V` (paste to send), `Ctrl+Shift+S` (send dialog), `Ctrl+,` (settings), `F1` (help).
- **Türkçe + İngilizce dil dosyaları** Windows-specific string'lerle genişler ("UAC", "Defender", "SmartScreen").

### Dokümantasyon & Topluluk
- **Windows-specific install guide** (`docs/install/windows.md`): Defender false-positive giderme, firewall exception.
- **Blog post** (iç, yayınlanmaz): "Azure Trusted Signing ile Rust app imzalama rehberi" — v1.0.0 sonrası yayın.

### KPI (Q3 Sonu)
- ✅ Windows `.exe` + `.msix` imzalı ve SmartScreen'de "clean".
- ✅ Auto-update signed ve rollback test edildi.
- ✅ Winget + Scoop manifest hazır, submission bekliyor.
- ✅ Windows 10 + 11 + ARM64'te smoke test pass.
- ✅ Private beta kullanıcı sayısı 150'ye çıktı.

### Riskler (Q3)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| Azure Trusted Signing onay gecikir | Orta | Orta | Yedek: DigiCert EV cert ($400/yıl), hazırda bekle |
| SmartScreen ilk indirmeleri uyarır | Yüksek | Düşük | Beta kullanıcılara "yine de çalıştır" rehberi; 1000+ indirme sonrası reputation temizlenir |
| WebView2 eski Windows 10 sürümlerinde çökme | Orta | Orta | Minimum version Windows 10 v1903; daha eski sürümlerde açık reddet |
| Windows ARM64 çapraz derleme sorunları | Düşük | Düşük | `cross` kullan; x86_64 emülasyon fallback |

### Karar Kapısı Q3→Q4
- **Go:** Windows 3 mimaride imzalı build, auto-update test geçti, Winget/Scoop manifest PR kuyruğunda.
- **No-go:** Signing sorunu varsa, Q4'e kaydırılır; macOS önce gelir.

---

## Q4 — "macOS Succession" (Ay 10-12, 2027-02 → 2027-04)

### Tema & Amaç
NearDrop'un Eylül 2026 Homebrew zorunluluğu başlamadan önce macOS'ta miras devral. Developer ID + notarize + Sparkle 2 + Finder/Safari Share Extension'ları + resmi Homebrew Cask (tap değil, ana repo). NearDrop'un 6.1k kullanıcısına migration path sun. Menu-bar first UX, share-sheet integration — NearDrop'un iyi yaptığı her şey + onun yapmadıkları (trusted devices, folder, bidirectional, auto-update).

### Teknik Deliverable'lar

**v0.13.0 — Developer ID + Notarize + Sparkle 2 (2027-03-31)**
- **Apple Developer Program** üyeliği ($99/yıl) — büyük ihtimal zaten var, değilse kur.
- **Developer ID Application** sertifikası; CI'ya secret enjeksiyonu.
- **Notarization pipeline**: `xcrun notarytool` CI entegrasyonu; stapling.
- **Sparkle 2** integration (Sparkle 1 değil — 2 daha modern, EdDSA signing).
  - Appcast: `https://hekadrop.dev/appcast.xml`
  - Ed25519 signing key (offline HSM'de muhafaza edilir).
  - Delta updates (Sparkle native support).
  - Channel: `stable` vs `beta` — beta kullanıcılar `beta` channel.
- **macOS Entitlements**: minimum gerekli (Network, LAN, Local Network usage description). Sandbox değerlendirmesi (MAS için gerekli, Developer ID için opsiyonel).
- **LaunchAgent** `~/Library/LaunchAgents/dev.hekadrop.plist` — login item olarak kaydedilebilir (SMLoginItemSetEnabled).
- **Universal2 binary** (arm64 + x86_64) — zaten var, doğrulanır.
- **Privacy manifest** (`PrivacyInfo.xcprivacy`) — Apple'ın 2024+ zorunluluğu; Wi-Fi discovery justification.

**v0.14.0 — Share Extensions (2027-04-30)**
- **Finder Share Extension**: macOS App Extension (Swift/Objective-C glue katmanı — `extensions/finder-share/`). Right-click → Share → HekaDrop.
  - Rust core ile XPC veya unix socket üzerinden konuşur.
  - Native picker UI: peer listesi + PIN onay.
- **Safari Share Extension**: aynı pattern; page URL / PDF / image share.
- **Quick Look plugin** (opsiyonel): `.hekadrop` paket dosyası önizleme (ileride NAS export formatı).
- **macOS Shortcuts integration**: "Send file to phone" shortcut action.
- **Services menü entry**: "Send to phone via HekaDrop" — sistem genelinde cross-app.
- **QR code fallback**: Mac→Android senaryosunda peer görünmüyorsa QR code göster (NearDrop 2.2.0 paritesi ama fallback olarak, varsayılan değil).
- **Menu-bar only mode**: Dock icon gizlenebilir (`LSUIElement=YES` toggle setting'den).

### Ops/Altyapı
- **Resmi Homebrew Cask**: `homebrew-cask` ana repo'suna PR. Hazırlık ama submission v1.0.0'da.
  - Cask dosyası: `Casks/h/hekadrop.rb` (zaten var, güncellenir).
  - Notarization stapling doğrulanır (homebrew 5.0+ zorunluluğu).
- **Mac App Store değerlendirmesi**: Sandbox testleri başlar, ama submission v1.1.0 sonrası (çok fazla sandbox friction, audit report sonrası karar).
- **DMG vs ZIP**: `.dmg` notarize + staple; ayrıca ZIP cask için.
- **Code signing audit**: `codesign -vv --deep --strict HekaDrop.app` CI'da her release.

### Güvenlik
- **Audit ilerleme**: Q2-Q3'te başlayan audit Q4'ün ortasında kapanır (beklenen: 4-5 aylık engagement).
- Bulgular `SECURITY-ADVISORIES.md` draft'a girer; coordinated disclosure timeline.
- macOS-specific threat model:
  - LaunchAgent privilege escalation
  - XPC boundary between extension and daemon
  - Keychain usage for trust secrets (opsiyonel — v1.0.0'da karar)

### UX/Polish
- **Menu-bar icon**: Animasyonlu (transfer sırasında), template image (dark/light mode uyumlu).
- **Notification Center**: macOS native banner + alert, inline action buttons (Accept/Reject/Open Folder).
- **Finder integration**: İndirilen dosya için "Reveal in Finder" link notification'da.
- **Native Cmd+Shift+H shortcut**: global hotkey setting.
- **Dark mode**: automatic, system follow (zaten var, doğrulanır).
- **Accessibility**: VoiceOver uyumluluğu audit — tüm button'lar labeled, keyboard navigation çalışır.

### Dokümantasyon & Topluluk
- **NearDrop migration guide** (`docs/migrate/neardrop.md`): NearDrop trust store'u import et, download dizini eşle, login item migrate.
- **Homebrew install guide** (v1.0.0 için hazır, henüz yayınlanmaz).
- **Video demo** (30 saniye, muted): Finder right-click → Send → iPhone/Android notification. YouTube + landing page.

### KPI (Q4 Sonu)
- ✅ macOS notarize pipeline çalışır, her release Gatekeeper pass.
- ✅ Sparkle 2 update testi: eski → yeni transition + rollback.
- ✅ Finder Share Extension sistem genelinde görünür.
- ✅ Homebrew Cask PR tamamen hazır, submission kuyruğunda.
- ✅ Private beta kullanıcı sayısı 300'e çıktı; %40'ı macOS.
- ✅ Audit bulguları (Q4 sonu beklenen) çözüm PR'ları başlamış.

### Riskler (Q4)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| Apple notarize reddi (unsigned dependency) | Orta | Orta | `codesign --deep` + Rust library signing; `otool -L` temiz |
| Share Extension XPC permission karmaşası | Orta-Yüksek | Orta | Early prototype Q4 başında; Apple Developer Forums + Stack Overflow |
| Audit Q4'ü aşar | Orta | Yüksek | Audit paralel Q5'e taşınır; Q5 deliverable'ları iki hafta kayar |
| macOS Sequoia (14) → Tahiti (15) breaking changes | Orta | Orta | macOS beta ile CI; WWDC haziran 2027'de uyum sprinti |
| Menu-bar icon HiDPI sorunları | Düşük | Düşük | Vector (PDF) asset |

### Karar Kapısı Q4→Q5
- **Go:** macOS notarize + Sparkle + Share Extensions çalışır; audit bulguları yönetilebilir severity'de.
- **No-go:** Audit high-severity açığı çıkarsa, Q5 protocol değil güvenlik sprintine çevrilir; v0.15 yerine v0.14.x hotfix'ler çıkar.

---

## Q5 — "Dual Protocol" (Ay 13-15, 2027-05 → 2027-07)

### Tema & Amaç
Kimsede olmayan pozisyonu al: **tek binary, iki protokol**. LocalSend v2'yi implement et; bizim Quick Share + LocalSend unified receiver olalım. 78.7k yıldızlık LocalSend topluluğuna "LocalSend kullanıcılarından da dosya alın, üstüne stock Android Quick Share share sheet'ine de açıksınız" pozisyonu. Bu, hiçbir rakibin yapısal olarak ulaşamayacağı bir konsolidasyon.

### Teknik Deliverable'lar

**v0.15.0 — LocalSend v2 Receive (2027-06-30)**
- **Protokol implementasyonu**: `crates/hekadrop-core/src/localsend/`:
  - UDP multicast `224.0.0.167:53317` announce + listen
  - HTTPS self-signed cert server
  - Endpoint'ler: `/api/localsend/v2/prepare-upload`, `/upload`, `/cancel`, `/register`, `/prepare-download`, `/download`
  - Fingerprint SHA-256 hesabı
  - PIN auth flow
- **Unified `Peer` domain tipi**: `PeerProtocol::QuickShare | PeerProtocol::LocalSend`; UI'da rozet.
- **Unified `Transfer` event stream**: ikisi de aynı progress/cancel API'sini kullanır.
- **Unified trust store**: Quick Share trusted device + LocalSend favorites aynı settings sekmesinde birleşir.

**v0.16.0 — Dual-Receiver Unified UX (2027-07-31)**
- **Multi-protokol simultaneous**: aynı anda iki protokol dinler, conflict yok.
- **Send side**: kullanıcı dosya sürükler → peer picker hem Quick Share hem LocalSend peer'larını gösterir; peer tipine göre doğru protokol seçilir.
- **LocalSend web-receiver fallback**: browser'dan `http://<host>:53317/` → LocalSend upload UI (LocalSend spec zaten tanımlıyor).
- **Magic Wormhole transit opsiyonel** (uzun vadeli): internet üzerinden word-code ile transfer; Warp uyumluluğu. Sadece prototype Q5'te, release Q7-Q8.
- **Protocol negotiation**: Peer iki protokolde de görünürse tercih Quick Share (bizim native).

### Ops/Altyapı
- **Real-device interop matrix genişler**: LocalSend Android + iOS + Windows peer'ları CI'da.
- **Self-signed TLS cert rotation**: LocalSend için 1 yıl validity, auto-regenerate.
- **mDNS vs multicast çakışma**: aynı NIC iki farklı discovery, conflict testi.

### Güvenlik
- **Audit final report** yayınlanır (Q4 sonunda veya Q5 başında biter). Fixes entegre edilir.
- LocalSend protokolünde self-signed fingerprint pinning tartışması: ilk-connection TOFU (trust on first use) mi, QR pairing mi? Varsayılan TOFU + manual fingerprint confirm.
- **Bug bounty programı hazırlık**: HackerOne veya kendi hosted programı için policy draft.

### UX/Polish
- **Peer list UI**: ikon + protokol rozeti + alias + cihaz tipi. Filter: "Sadece Quick Share", "Sadece LocalSend", "Hepsi".
- **İlk çalıştırma wizard**: "Telefonunuzda hangi app var?" — kullanıcıya protokol bilgisi verir.
- **Trust onboarding**: ilk LocalSend connection'da fingerprint göster, kullanıcı onaylar.

### Dokümantasyon & Topluluk
- **Blog post** (yayın v1.0.0'a kadar beklenir ama yazılır): "Bir Receiver, İki Protokol — HekaDrop'un Dual-Protocol Mimarisi".
- **LocalSend topluluğuna bilgi**: LocalSend issue'da "working on interop" şeffaf comment (Tienisto karşı çıkmazsa).
- **Public beta portal**: private beta → public beta'ya evrim (Q6'da karar).

### KPI (Q5 Sonu)
- ✅ LocalSend peer'dan dosya alıyoruz, smoke test pass.
- ✅ LocalSend peer'a dosya gönderiyoruz, smoke test pass.
- ✅ Web receiver (`http://host:53317/`) browser'dan çalışır.
- ✅ Audit final report alınmış, high-severity bulgular 0, medium 3'ün altında.
- ✅ Beta kullanıcı sayısı 600.

### Riskler (Q5)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| LocalSend v3 spec çıkar | Düşük | Orta | Tienisto aktif değil, v2 spec stable |
| Protokol conflict (port 53317 başkası) | Düşük | Düşük | LocalSend zaten rezerve, iyi davranış |
| Audit high-severity bug | Orta | Yüksek | Q5 hotfix sprint'i hazırda |
| Dual UX karmaşası kullanıcıyı boğar | Orta | Orta | User research (beta kullanıcılar); progressive disclosure |

### Karar Kapısı Q5→Q6
- **Go:** Dual protokol calisti, audit kapandi, beta kullanici memnuniyet NPS > 40.
- **No-go:** Protokol interop edge case'leri 4+ hafta sürerse, Q6 ekosistem işi iki hafta kayar.

---

## Q6 — "Ecosystem" (Ay 16-18, 2027-08 → 2027-10)

### Tema & Amaç
Masaüstü + mobil senaryonun dışına çık: homelab, NAS, ev otomasyonu. Docker image, Synology/Unraid/TrueNAS paketleri, Home Assistant integration, headless web admin. Bu, HN/Reddit r/selfhosted/homelab viral senaryonun motoru. Aynı zamanda v1.0.0 launch'ta "sadece masaüstü app değil, ekosistem" hikayesi.

### Teknik Deliverable'lar

**v0.17.0 — Docker + NAS Paketleri (2027-09-30)**
- **Docker image**: `ghcr.io/yatogamiraito/hekadrop`:
  - Multi-arch: linux/amd64, linux/arm64, linux/arm/v7 (Raspberry Pi 4)
  - Base: `distroless/cc-debian12` (~5 MiB + binary)
  - Volume: `/config` (trust store, settings), `/downloads`
  - Port: 53317/tcp (LocalSend HTTPS), 53317/udp (LocalSend multicast), random/tcp (Quick Share)
  - `HEKADROP_DEVICE_NAME`, `HEKADROP_AUTO_ACCEPT_TRUSTED`, `HEKADROP_DOWNLOAD_DIR` env vars
  - Health check endpoint: `http://localhost:9090/health` (Prometheus metrics opsiyonel)
- **docker-compose.yml** örnek (host network mode LAN discovery için).
- **Kubernetes Helm chart** (opsiyonel, v1.0.0 sonrası): StatefulSet + Service.
- **Synology SPK**: DSM 7+ uyumlu; Package Center'a submission v1.0.0'da. `resource.json`, `start-stop-status` script'leri.
- **Unraid community app**: XML definition, GitHub Apps store.
- **TrueNAS SCALE plugin**: zaten Docker tabanlı, Helm chart ile entegrasyon.
- **OpenWrt/EdgeOS opsiyonel**: ARM builds hazır.

**v0.18.0 — Home Assistant + Web Admin (2027-10-31)**
- **Home Assistant custom integration** (`homeassistant/custom_components/hekadrop/`):
  - Entities: `sensor.hekadrop_last_received`, `sensor.hekadrop_active_transfers`
  - Services: `hekadrop.send_file`, `hekadrop.notify_peer`
  - Events: `hekadrop_file_received` (automation trigger)
  - Config flow: UI-based setup
- **HACS submission** hazırlığı (v1.0.0'da).
- **Web admin UI**: `/admin` endpoint (LocalSend server üzerinden, auth'lu):
  - Transfer log, peer list, settings edit, log download
  - Responsive (mobil yönetim için)
  - Dark/light mode
- **Metrics endpoint**: Prometheus-uyumlu `/metrics`; Grafana dashboard örnek dosyası `docs/deploy/grafana/`.

### Ops/Altyapı
- **ghcr.io push pipeline**: release tag → multi-arch image push + signed manifest (cosign).
- **Docker Hub mirror** (opsiyonel): community expectation.
- **Container scanning**: Trivy, Grype CI adımı; 0 high-severity CVE.
- **Reproducible Docker builds**: `docker buildx --output type=oci` ile tag-bağımsız.

### Güvenlik
- **Headless mode threat model**: web admin auth (API token + session), CSRF, same-origin.
- **Docker rootless mode** desteklenir; başlangıçta `USER 10001:10001`.
- **Supply chain**: `cosign sign` + `cosign verify` dokümantasyonu.

### UX/Polish
- **Web admin UX**: Minimal, Tailwind veya Pico.css; JS minimum.
- **Docker health check mesajları**: meaningful stdout log (systemd ready).
- **Home Assistant config flow**: device-picker UI.

### Dokümantasyon & Topluluk
- **`docs/deploy/` genişler**:
  - `docker.md`, `synology.md`, `unraid.md`, `truenas.md`, `home-assistant.md`, `proxmox.md`, `systemd.md`
- **Tutorial video**: "HekaDrop on Synology — 5 Minute Setup" (v1.0.0 launch kampanyası için hazırlanır).
- **r/selfhosted** + **r/homelab** için hazır launch post taslakları.

### KPI (Q6 Sonu)
- ✅ Docker image `docker pull` ile çalışır 3 mimaride.
- ✅ Synology/Unraid/TrueNAS'ta test edildi (gerçek donanım veya VM).
- ✅ Home Assistant integration local install çalışır, 2 automation örneği dokümante.
- ✅ Web admin basic security audit geçti.
- ✅ Beta kullanıcı 1000+, NAS kullanım %15+.

### Riskler (Q6)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| Docker host network LAN discovery CNI ile çakışma | Orta | Orta | Doküman net; `network_mode: host` zorunluluğu |
| Synology DSM 7 API değişir | Düşük | Orta | SPK periyodik sync |
| HA config flow breaking change | Orta | Düşük | HA nightly CI |
| Web admin XSS/CSRF | Orta | Yüksek | Q6 güvenlik mini-audit |

### Karar Kapısı Q6→Q7
- **Go:** Ekosistem paketleri 4 platformda çalışır, HA integration HACS-ready.
- **No-go:** Docker güvenlik sorunu varsa Q7 başına kayar.

---

## Q7 — "Transport Breadth" (Ay 19-21, 2027-11 → 2028-01)

### Tema & Amaç
mDNS/LAN-only kısıtını aş. BLE advertising (Android background discovery hızlanır, battery friendly), Wi-Fi Direct fallback (SHAREit'in tek gerçek avantajı — airport/hotel/kafe senaryosu), hotspot mode. Bu transport'lar olmadan v1.0.0 "gerçekten her yerde çalışır" iddiasında boşluk kalır.

### Teknik Deliverable'lar

**v0.19.0 — BLE Advertising Full Stack (2027-12-31)**
- **Linux**: `bluer` (rquickshare'in seçimi). BlueZ 5.50+.
- **macOS**: CoreBluetooth bridge (Objective-C FFI katmanı).
- **Windows**: `windows-rs` Windows.Devices.Bluetooth.Advertisement API.
- **BLE advertisement format**: Google'ın Quick Share BLE spec'i (`_FC9F5ED42C8A` UUID, encoded endpoint info).
- **Background discovery**: laptop kapalı tray'de dinlemeye devam eder; Android telefon Quick Share share sheet açtığında BLE ile hızlı bulur.
- **Battery budget**: BLE advertising default 10s interval, "low power mode" 60s.
- **Permission modelleri**:
  - macOS: Bluetooth usage description, ilk launch'ta prompt
  - Linux: `CAP_NET_ADMIN` veya polkit
  - Windows: tipik olarak UAC yok, ama app capability

**v0.20.0 — Wi-Fi Direct Fallback + Hotspot (2028-01-31)**
- **Wi-Fi Direct / Wi-Fi Aware** (platform uyumluluğuna göre):
  - Linux: `wpa_supplicant` P2P API
  - macOS: Multipeer Connectivity framework (yüksek seviye)
  - Windows: Wi-Fi Direct API (COM)
- **Fallback flow**: aynı LAN'da peer görünmüyor → BLE advertisement görünüyor → hotspot/Wi-Fi Direct negotiation.
- **Hotspot mode**: HekaDrop kendi hotspot'unu açabilir (platform izin verirse) veya peer'ın hotspot'una bağlanabilir.
- **Airport senaryosu test**: iki cihaz farklı SSID'de, discovery sağlanır, transfer başlar.
- **Wi-Fi Aware (iOS 26 + Linux NAN) prototip**: sadece Linux kernel NAN backport edildiğinde. Release v1.1.0'a kayabilir.

### Ops/Altyapı
- **BLE testi için donanım**: USB BT adapter'lı test PC'ler.
- **Wi-Fi Aware kernel desteği takibi**: Linux 6.x backport durumu izlenir.
- **CI:** BLE hardware-in-the-loop self-hosted runner.

### Güvenlik
- **BLE advertisement privacy**: MAC randomization; static identifier'lar encoded endpoint info içinde değil.
- **Wi-Fi Direct pairing**: PIN + UKEY2 üzerine; MITM koruması.
- **Permission audit**: her transport için minimum gerekli izin.

### UX/Polish
- **Discovery sırası göstergesi**: "mDNS ile arıyor... BLE ile arıyor... Wi-Fi Direct teklif ediliyor..."
- **Fallback açıklaması**: kullanıcıya "Aynı ağda değilsiniz, BLE ile bağlanılıyor" mesajı.
- **Battery indicator** (laptop): "BLE advertising açık — pil etkisi düşük".

### Dokümantasyon & Topluluk
- **`docs/protocol/transport-stack.md`**: tüm transport katmanlarını anlatan tek doküman.
- **Blog post** (v1.0.0 launch için hazırlanır): "Airport Hotspot'unda Dosya Göndermek — HekaDrop'un Transport Stack'i".

### KPI (Q7 Sonu)
- ✅ BLE advertising 3 platformda çalışır.
- ✅ Wi-Fi Direct fallback smoke test: iki farklı SSID cihaz transfer tamamladı.
- ✅ Battery impact ölçüm: ≤ %3 ek drain/saat.
- ✅ Beta kullanıcı sayısı 1500, positif NPS.

### Riskler (Q7)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| Windows BLE API nuances | Yüksek | Orta | Erken prototype; community Rust BLE libs |
| macOS CoreBluetooth FFI karmaşası | Yüksek | Yüksek | Ayrı ekspertise; dış kontraktör gerekebilir |
| Wi-Fi Direct Linux `wpa_supplicant` config | Yüksek | Orta | Debian/Fedora/Arch 3 distro paralel test |
| BLE advertising Android uyumluluk Samsung ROM'unda kırık | Orta | Yüksek | One UI 6/7 matrix CI; fallback mDNS-only |

### Karar Kapısı Q7→Q8
- **Go:** BLE + Wi-Fi Direct her ana platformda çalışır (en azından manual test).
- **No-go:** Wi-Fi Direct kritik platformda çalışmazsa v1.0.0'da opsiyonel feature olarak, v1.1.0'da tam destek.

---

## Q8 — "1.0.0 Launch" (Ay 22-24, 2028-02 → 2028-04)

### Tema & Amaç
Tüm parçaları birleştir, feature freeze, kapsamlı RC döngüsü, launch kampanyası, tüm paket yöneticilerine eş zamanlı submission. Bu fazın disiplini, 23 ayın çalışmasını satar.

### Teknik Deliverable'lar

**v0.99.0-rc.1 — Feature Freeze (2028-02-29)**
- Yeni feature yok; sadece bug fix + polish.
- **i18n final push**: 15+ dil hedefi:
  - Core: Türkçe, İngilizce (zaten var)
  - Avrupa: Almanca, Fransızca, İspanyolca, İtalyanca, Portekizce, Hollandaca
  - Asya: Mandarin (Simplified), Japonca, Korece, Hintçe
  - Slav: Rusça, Lehçe, Ukraynaca
  - Diğer: Arapça (RTL test), Brezilya Portekizcesi
- **Translation vendor** veya Crowdin/Weblate kurulur; topluluk çevirisi.
- **Accessibility final pass**: VoiceOver (macOS), NVDA (Windows), Orca (Linux) test.
- **Tüm hata mesajları** i18n kapsamında.
- **README** 15 dilde `README.{lang}.md`.

**v0.99.0-rc.2 — Localization Complete (2028-03-15)**
- Tüm çeviriler merged.
- **Installer dialog strings** her platform için i18n.
- **Notification strings** i18n.
- Dokümantasyon sitesi en az 5 dilde.

**v0.99.0-rc.3 — Audit Fixes Integrated (2028-04-01)**
- Audit raporundan kaynaklı tüm fixes merged.
- **Final security review** (Cure53 spot-check opsiyonel).
- **Reproducible builds** doğrulanır (3 farklı ortam, aynı binary).
- **Performance benchmark**: 1 GiB dosya 1 Gbps LAN'da ≤ 15 saniye hedefi.

**v1.0.0 — Public Launch (2028-04-24)**
- Feature freeze üzerine sadece critical hotfix'ler.
- **Launch-day binary'leri hazır**: macOS (dmg + zip), Windows (msix + msi + exe), Linux (deb, rpm, AppImage, Flatpak, Snap, AUR, Nix, tarball).
- **Paket yöneticisi submission'ları otomasyonlanmış**: CI her release'de submit PR'ı açar.

### Ops/Altyapı: Paket Yöneticisi Submission Çağlayanı

Launch gününden sabah 08:00 ET öncesi kuyruklanan, sıraya göre işleyen PR'lar:

1. **Homebrew Cask** (`homebrew-cask` ana repo'su) — notarize-ready, auto-PR.
2. **Winget** (`microsoft/winget-pkgs`) — `wingetcreate submit`.
3. **Scoop** (bucket: `scoop-extras` veya ana) — manifest PR.
4. **Flathub** — `org.hekadrop.HekaDrop`, manifest + test wave.
5. **Snap Store** — `snapcraft upload`, strict confinement + network permission.
6. **AUR**: `hekadrop-bin` (binary), `hekadrop` (source) — iki paket.
7. **Nixpkgs** — master PR.
8. **Debian/Ubuntu** PPA veya resmi pakete başvuru (resmi süreç uzun, ayrıca).
9. **Fedora Copr** + resmi başvuru.
10. **openSUSE Build Service**.
11. **Chocolatey** — moderation süresi uzun, opsiyonel.
12. **Mac App Store** — sandbox compliance bittiğinde, v1.0.x'te (muhtemelen v1.0.1).
13. **Microsoft Store** — MSIX submission, v1.0.x'te.
14. **Google Play (Android-side companion?)** — roadmap v1.1.x'te.

### Güvenlik
- **Bug bounty programı** aktive edilir (HackerOne veya kendi self-hosted).
- **Security advisories policy** yayınlanır: 90-gün coordinated disclosure.
- **Audit raporu public**: `docs/security/audit-2028.pdf` yayınlanır.

### UX/Polish
- **Onboarding tour**: ilk kurulumda 4 adım (cihaz adı, download dizini, tray davranışı, test transfer).
- **"What's new"** dialog her minor update'te (Sparkle + Windows updater).
- **Crash reporter** (opsiyonel, opt-in): Sentry veya self-hosted.

### Dokümantasyon & Topluluk (Launch Campaign)
- **Launch blog post (ana)**: `hekadrop.dev/blog/1.0` — "Two Years. Zero App on Your Phone. HekaDrop 1.0".
- **HN Tuesday 08:00 ET submission**: title A/B test edilmiş. Comments'e 2 maintainer nöbet tutar.
- **Lobsters submission**.
- **ProductHunt launch**.
- **Reddit submissions**: r/programming, r/rust, r/linux, r/macapps, r/selfhosted, r/homelab, r/degoogle, r/privacy, r/opensource, r/homeassistant.
- **Twitter/X thread** + **Mastodon/Fediverse thread**.
- **LWN pitch** (editor email, 1 hafta önce).
- **Verge + Ars Technica + The Register pitch** (1 hafta önce embargo).
- **OMG!Ubuntu + OMG!Linux pitch**.
- **It's FOSS** pitch.
- **Video demo** (90 sn + 5 dk teknik deep-dive) YouTube.
- **Press kit** (`hekadrop.dev/press`): logo, screenshots, fact sheet, founder photo.
- **Discord/Matrix public açılır** — moderator rota.

### KPI (v1.0.0 Launch Günü Sonu)
- ✅ HN front page (top 10) 4+ saat.
- ✅ Lobsters ilk sayfa.
- ✅ 24 saat içinde GitHub ★: 5k+; 1 hafta içinde 15k+; 1 ay: 30k+.
- ✅ 10+ paket yöneticisi submission merged.
- ✅ İlk 1000 gerçek kullanıcı (non-beta) 48 saat içinde.
- ✅ Basın coverage: 5+ tier-1 site.

### Riskler (Q8)
| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| HN downvote / submission zamanlaması kötü | Orta | Yüksek | A/B test title; alternatif Wednesday re-submission |
| Son dakika kritik bug | Orta | Yüksek | Hot-patch pipeline hazır; rollback plan |
| Homebrew Cask review 1+ hafta sürer | Orta | Orta | PR önceden açık, reviewer ping |
| Microsoft Store reddi | Orta | Düşük | v1.0.x'e öteleme planı |
| Sunucu load (indirme spike) | Orta | Orta | GitHub Releases CDN zaten ölçekli; bandwidth meter |
| Dil topluluğu çeviri gecikir | Orta | Orta | Top 5 dile öncelik; diğerleri v1.0.x'te |

---

## 4. Paralel Akımlar (24 Ay Boyunca Sürekli)

Aşağıdaki iş akımları çeyreklere bağımlı değil, süreklidir:

### 4.1. Güvenlik Akımı
- **Aylık `cargo audit` + `cargo deny` review**; advisory ignoreliste kontrol.
- **Haftalık dependency güncellemesi**; Dependabot/Renovate kuralları.
- **Her release öncesi**:
  - Fuzz 168 saat crash-free
  - `cargo-mutants` report
  - `cargo-vet` review (yeni doğrudan deps)
  - Threat model güncelleme (yeni transport/feature varsa)
- **Coordinated disclosure** süreci dokümante, tek giriş noktası `security@hekadrop.dev`.
- **Bug bounty**: v1.0.0'a kadar informal, v1.0.0'dan sonra formal (düşük $ baz).

### 4.2. Topluluk Akımı
- **Haftalık Discord/Matrix "office hours"** (ilk 12 ay 1 saat/hafta, Q5'ten sonra 2 saat/hafta).
- **Aylık "HekaDrop Update" blog postu**: yeni özellikler, topluluk katkıları, metrics.
- **Çeyrek-sonu "retrospektif"** public blog postu.
- **Çeviri portalı** Q4'ten sonra aktif (Crowdin veya Weblate self-hosted).
- **Contributor tanıma**: her release notes'unda katkı sağlayan listesi + GitHub profile.
- **Katkı yolu hazırlığı**: "good first issue", "help wanted" label disiplini.

### 4.3. Finansman Akımı
- **Q1:** GitHub Sponsors profil açılır, Patreon değerlendirilir.
- **Q2:** NLnet başvurusu (Privacy & Trust Enhancing Technologies, €50k hedef).
- **Q3:** Sovereign Tech Fund (Almanya, Alman open source fonu) başvurusu — Rust + güvenlik kritik projeler için uygun.
- **Q4:** OTF (Open Tech Fund) başvurusu — anti-censorship açısından zayıf, pas geçilebilir.
- **Q5:** OpenCollective kurulumu.
- **Q6:** ilk enterprise/NAS vendor sponsor outreach (Synology, Unraid, TrueNAS).
- **Q7-Q8:** v1.0.0 öncesi crowdfunding kampanyası opsiyonu (yalnızca finansman açığı varsa).

### 4.4. Ekip Büyümesi Akımı
- **Ay 0-3:** Solo (kurucu) + 1-2 part-time katkıcı.
- **Ay 3-6:** 3-5 regular contributor; 1 topluluk moderatörü gönüllü.
- **Ay 6-12:** Part-time macOS expert (Share Extension + CoreBluetooth için kritik — Q4-Q7). Budget/hibe varsa kontraktör, yoksa gönüllü.
- **Ay 12-18:** Dokümantasyon + devrel rolü (part-time veya gönüllü).
- **Ay 18-24:** Launch öncesi PR/iletişim desteği (kontraktör).

### 4.5. Hukuk/Lisans Akımı
- **Lisans**: mevcut MIT — v1.0.0'a kadar korunur. Apache-2.0 değerlendirilir (patent grant için); karar Q6'da.
- **CLA (Contributor License Agreement)**: Gerekli değil için karar. Tercih: CLA yok, DCO (Developer Certificate of Origin) var.
- **Trademark**: "HekaDrop" trademark başvurusu (en az TR + AB + ABD) Q4'te; $1-3k maliyet.
- **Privacy policy** (site için): GDPR uyumlu, `hekadrop.dev/privacy`.

### 4.6. Altyapı Akımı
- **Hosting**: `hekadrop.dev` — Cloudflare Pages (statik site).
- **Release binary dağıtımı**: GitHub Releases + Cloudflare R2 mirror (bandwidth maliyeti için).
- **Update server**: `updates.hekadrop.dev` — appcast.xml + signature verification endpoint.
- **CI**: GitHub Actions (ücretsiz tier → public repo). Self-hosted runner'lar real-device test için (RPi + laptop).
- **Monitoring**: GitHub Actions notification + Discord webhook; downtime için UptimeRobot.

---

## 5. Versiyonlama Politikası

- **SemVer** kesinlikle uygulanır:
  - **Major (1.x → 2.x)**: breaking API change in `hekadrop-core`, protokol geriye uyumsuzluğu, destek kaldırma.
  - **Minor (1.0 → 1.1)**: yeni feature, backward-compatible.
  - **Patch (1.0.0 → 1.0.1)**: bug fix, security fix.
- **v0.x**: API stabil değil, her minor breaking olabilir; ama biz yine de pragmatik davranırız.
- **v0.99.0-rc.N**: Q8'deki release candidate zinciri.
- **v1.0.0 sonrası**: v1.x hattı 18 ay desteklenir (LTS policy); v2.0 bu döngünün dışı.

---

## 6. Marka, İletişim ve Mesajlaşma

### 6.1. Tek Cümlelik Değer Önermesi
> "HekaDrop, telefonunuzda hiçbir uygulama gerektirmeden, dosyalarınızı yerel ağınız üzerinden masaüstünüze gönderen, Quick Share ve LocalSend protokollerini konuşan, tamamen açık kaynak ve ücretsiz bir Rust uygulamasıdır."

### 6.2. 3 Anahtar Mesaj
1. **Zero-app-on-phone:** "LocalSend iki app ister. HekaDrop telefonda sıfır app ister."
2. **Dual-protokol:** "Quick Share veya LocalSend — ikisinden hangisine sahipseniz HekaDrop onu konuşur."
3. **Gerçekten sizin:** "Bulut yok, hesap yok, tracker yok, kapalı kaynak dependency yok."

### 6.3. Rakip Karşılaştırmaları (Adil ve Doğru)
Launch'ta site'da bir karşılaştırma tablosu yayınlanır. Her satır doğrulanabilir, sansür yok:
| | HekaDrop | LocalSend | NearDrop | rquickshare |
|---|---|---|---|---|
| Telefonda app gerekir mi? | Hayır (Android) | Evet | Hayır (Android) | Hayır (Android) |
| macOS imzalı | ✅ | ✅ | ❌ | ❌ |
| Windows | ✅ | ✅ | ❌ | ❌ |
| Linux | ✅ | ✅ | ❌ | ✅ |
| Quick Share | ✅ | ❌ | ✅ | ✅ |
| LocalSend | ✅ | ✅ | ❌ | ❌ |
| Transfer resume | ✅ | ❌ | ❌ | ❌ |
| Auto-update (signed) | ✅ | ✅ | ❌ | ❌ |
| External security audit | ✅ | ❌ | ❌ | ❌ |
| Home Assistant | ✅ | ❌ | ❌ | ❌ |
| Docker | ✅ | ❌ | ❌ | ❌ |

### 6.4. Yapmayacağımız Şeyler (Açık Tutumu)
- Rakipleri kötülemek yok.
- "LocalSend öldü" retoriği yok (yanlış ve kaba).
- Abartılı performans iddiaları yok ("%100 daha hızlı" vb.).
- Açık ama nazik rakip karşılaştırması; herkesi referans verir.

---

## 7. Risk Register (Toplu)

| Kategori | Risk | Etki | Olasılık | Azaltma |
|---|---|---|---|---|
| Teknik | Quick Share protokol değişikliği | Yüksek | Orta | Interop CI + hızlı bakım; Samsung One UI regresyonları tarih: Q2/Q4 |
| Teknik | LocalSend v3 çıkarılır | Orta | Düşük | v2 spec donmuş, çok popüler; geçiş süresi olur |
| Teknik | macOS Share Extension XPC karmaşası | Yüksek | Orta-Yüksek | Erken prototype Q4 başında, dış kontraktör opsiyonu |
| Teknik | Wi-Fi Direct platform fragmentasyonu | Orta | Yüksek | v1.0.0'da "opsiyonel" işaretli, v1.1.0'da tam |
| Teknik | Rust ekosistem dependency EOL (GTK3) | Orta | Tek seferlik | Q5-Q6'da GTK4 geçişi `tao`/`wry` upstream'e bağlı |
| Güvenlik | Audit'te kritik bug | Yüksek | Orta | Q5'te 2 haftalık hotfix sprint buffer |
| Güvenlik | Code signing cert expire / lost | Yüksek | Düşük | Azure Trusted Signing managed; yedek plan dokümante |
| Ops | Sovereign Tech Fund reddi | Orta | Orta | NLnet + GitHub Sponsors + OpenCollective paralel; budget azaltma planı |
| Ops | Release pipeline CI minute overflow | Düşük | Düşük | Public repo = unlimited; self-hosted tamamlayıcı |
| Pazar | LocalSend maintainer geri döner ve hızlı hareket eder | Orta | Orta | Bizim wedge'imiz yapısal (Quick Share interop); onların harekâtı bize dokunmaz |
| Pazar | Google kapalı kaynak Linux/macOS Quick Share çıkarır | Orta | Düşük | Hâlâ "açık kaynak + dual protocol" değer önermesi korunur |
| Pazar | Apple AirDrop'u başka platformlara açar | Düşük | Yüksek | iOS 26 AWDL→Wi-Fi Aware göçü fırsat da olabilir |
| Pazar | Samsung kendi Quick Share'i açık kaynak yapar | Düşük | Orta | Bizim için workload azalır; fork olarak değerlendirilir |
| Topluluk | Bus factor 1 (solo kurucu) | Yüksek | Yüksek | Kritik bilgi dokümante; en az 1 co-maintainer hedef Ay 12 |
| Topluluk | Toxic community incident | Orta | Düşük | Code of Conduct net; moderator rota Q5'ten sonra |
| Hukuk | Trademark ihtilafı ("Heka" zaten var) | Düşük | Orta | Trademark search Q3'te; gerekirse rename (geç, zor) |
| Hukuk | Lisans ihlali / patent claim | Düşük | Yüksek | MIT + Apache patent grant değerlendirmesi; cargo-vet |
| Launch | HN downvote / kötü timing | Orta | Yüksek | Önceden draft post; alternatif tarih; Lobsters backup |
| Launch | Apple/Microsoft Store reddi | Orta | Düşük | GitHub Releases zaten ana dağıtım; store opsiyonel |
| Finansman | Hibe reddi chain (NLnet + STF + OTF hepsi red) | Düşük-Orta | Yüksek | GitHub Sponsors + self-funded (düşük maaş, daha uzun takvim) |

---

## 8. Bütçe Tahminleri (Orta Çaplı Projeksiyon)

| Kategori | 24 Ay Toplam | Açıklama |
|---|---|---|
| Apple Developer Program | $198 | $99 × 2 yıl |
| Azure Trusted Signing | ~$240 | $10/ay × 24 |
| Domain (hekadrop.dev) + Cloudflare | ~$60 | 2 yıl |
| Trademark başvurusu | $1-3k | TR + AB + ABD |
| Crypto audit (Trail of Bits/Cure53) | $40-80k | NLnet hibe hedef |
| Self-hosted CI donanımı (RPi + NUC + test cihazları) | ~$2k | Bir defaya mahsus |
| Contractor (macOS expert, Q4-Q7) | ~$15-30k | Part-time |
| Çeviri (profesyonel, 8 dil x ~50k kelime) | ~$5-10k | Crowdin community ile indirilir |
| Launch kampanyası (reklam değil, press outreach) | ~$1k | Çoğu organik |
| **Toplam (medyan tahmin)** | **$70-130k** | |

Finansman stratejisi: NLnet %50+, GitHub Sponsors + OpenCollective %30, Sovereign Tech Fund %15, kendi cebimizden %5. Hibe chain başarısızlığında kapsam daralır (audit ertelenir, launch gecikir).

---

## 9. Başarı Tanımı (24 Ay Sonunda)

### 9.1. Asgari Başarı (Base Case)
- v1.0.0 yayınlandı, tüm ana paket yöneticilerinde mevcut.
- 15k+ GitHub yıldız, 500+ forks.
- 3+ tier-1 basın coverage.
- 50k+ toplam indirme (Homebrew analytics + Winget + GitHub Releases + Flathub vb.).
- 100+ contributor, 10+ düzenli core contributor.
- Güvenlik audit'i yayınlandı, 0 open critical CVE.
- Aktif topluluk: Discord/Matrix 1000+ üye, haftalık 100+ mesaj.

### 9.2. Hedef Başarı (Target Case)
- 50k+ GitHub yıldız.
- 250k+ indirme.
- 5+ sponsor/corporate sponsor.
- NAS vendor partnership (Synology/Unraid/TrueNAS'tan en az biri resmi paket).
- 30+ dil çevirisi.
- Linux Foundation veya NumFOCUS benzeri vakıf değerlendirmesi.

### 9.3. Hayalperest Başarı (Upside Case)
- 100k+ yıldız (bu 1M yıldız dedik, ama gerçekçi 24-ay upside 100k).
- 1M+ indirme.
- macOS native framework tercihi (Apple'dan API erişim desteği).
- Google/Samsung resmi partnership.
- Android companion app (v1.1.0+).
- Wi-Fi Aware üzerinden "açık AirDrop" pozisyonu.

**Not:** "1M yıldız" 24 ayda LocalSend bile değil (78.7k, 4 yılda). Gerçekçi 24-ay hedef 15-50k ★. 1M hedef 5-7 yıllık ufuk.

---

## 10. Bu Hafta Başlanacaklar (Concrete Next Actions)

1. **[Proje yönetim]** Bu `ROADMAP.md` merge edilir `main` branch'ine.
2. **[Proje yönetim]** GitHub Projects board kurulur: her çeyrek bir milestone, her v0.x.0 bir release hedef.
3. **[Teknik]** `refactor/pr5-review-fixes` branch'indeki uncommitted değişiklikler (src/connection.rs, src/sender.rs) review + commit/discard.
4. **[Teknik]** Workspace refactor RFC yazılır `docs/rfcs/0001-workspace-refactor.md`.
5. **[Teknik]** `send_url` karar RFC: implement et veya kaldır — `docs/rfcs/0002-url-payload.md`.
6. **[Ops]** GitHub Actions'ta `cargo-fuzz` entegrasyonu deneme PR'ı.
7. **[Topluluk]** Discord server kurulur, Matrix bridge hazırlanır (iç kullanım).
8. **[Hukuk]** Trademark search "HekaDrop" — TMEP, EUIPO, TÜRKPATENT.
9. **[Finansman]** GitHub Sponsors profili açılır (henüz Patreon değil).
10. **[Dokümantasyon]** `hekadrop.dev` domain kayıt + Cloudflare Pages kurulumu (statik landing page, "stealth" bildirimi).

---

## Ek A — Mimari Prensipler (24 Ay Boyunca İhlal Edilmez)

1. **Telefonda app gerektirmeyen her durumda o yol tercih edilir.** Android side app düşünülmez; sadece desktop protokol uyumluluğu üzerinden.
2. **Protocol engine UI'dan ayrılmış olarak kalır.** Tek core library + çoklu frontend (GUI, CLI, daemon, web).
3. **Her ağ paketinin kökeni denetlenir.** Trust sınırı açık: LAN peer, trusted peer, remote peer (v1.1+).
4. **Zero-trust default**: İlk bağlantıda PIN zorunlu, TOFU değil. Trusted devices kullanıcı aktivasyonuyla eklenir.
5. **Tüm kritik operasyonlar (crypto, trust, transfer kabul) test kapsamında**: property-based + integration + fuzz.
6. **Hiçbir telemetry/analytics yok** (opt-in bile değil). Crash reporter opsiyonel ama opt-in, self-hosted default.
7. **Minimum privilege**: Her platform için en az izin ile çalışır. Root/admin istemez.
8. **Açık dağıtım**: Homebrew Cask, Winget, Scoop, Flathub gibi merkezi olmayan yollar birincil; Apple/Microsoft Store ikincil.
9. **Geriye uyumluluk**: v1.0'dan sonra protokol değişikliği backward-compatible opt-in flag arkasında.
10. **Şeffaflık**: Güvenlik advisory, audit raporu, architecture decisions hepsi public.

---

## Ek B — Başlangıç Durumu Snapshot'ı (2026-04-24)

- **Branch:** `refactor/pr5-review-fixes`
- **Son commit:** `57e7cc9` fix: PR #75-#77 review yorumları + #78 orphan i18n key'leri canlandır
- **Uncommitted:** `src/connection.rs`, `src/sender.rs` (modified)
- **Mevcut test coverage:** ~3300 LOC integration, criterion crypto bench
- **Mevcut i18n:** TR + EN
- **Mevcut platform desteği:** macOS Universal2, Linux x86_64 (.deb), Windows x86_64 (.exe unsigned)
- **Mevcut release:** v0.6.0 henüz yayınlanmamış; Homebrew Cask var (tap: yatogamiraito/tap)
- **Crate yapısı:** tek binary + minimal lib.rs
- **Known issues:** #17 (trust race), GTK3 EOL, README overclaim (URL send)

---

**Bu doküman 2026-04-24 tarihli, 24 aylık v1.0.0 hedefli yaşayan dokümandır. Her çeyrek sonunda retrospektif ile güncellenir. Değişiklikler `git log docs/ROADMAP.md` üzerinden takip edilir.**
