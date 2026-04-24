# Bağımlılık Güncellik Politikası

Belge tarihi: **2026-04-24**
Hedef sürüm: **v0.7.0 → v1.0.0 (2028-04-24)**
İlgili: [`CONTRIBUTING.md`](../CONTRIBUTING.md), [`deny.toml`](../deny.toml)

## İlke

HekaDrop **agresif güncellik** politikası uygular. Prensip olarak her crate, takvimsel
olarak en son stabil minor sürümde tutulur. Ancak **upstream blokajlar** dolayısıyla bir
alt küme zorunlu olarak eski sürümde kilitlidir; bu kilitlerin her biri bu belgede
dokümante edilir ve kilit kalktığında ilk iş olarak PR açılır.

**Neden agresif?**
- Güvenlik fix'leri genelde son sürümlerde; eski sürümde kalmak CVE gecikmesi demek.
- Crypto crate'lerinde (p256, hkdf, hmac, aes, cbc, sha2, subtle) audit hattı en yeniyi hedefler.
- Ekosistem 6-12 aylık arkaya düşüldüğünde onarılması hızla pahalılaşır; küçük adımlarla düzenli
  yükseltme, büyük "big bang" yükseltmeden çok daha ucuz.

**Neden kilitler kabul edilir?**
- Cross-platform native GUI için `tao` + `wry` tek gerçekçi seçenek (Tauri ekosistemi).
- `wry` Linux'ta WebKit'i `webkit2gtk-rs` üzerinden gömer; `webkit2gtk-rs` hâlâ GTK3.
- GTK4 migration upstream'de süreç halinde ama 2026-04 itibariyle tamamlanmamış.

---

## 1. Mevcut blokaj zinciri (2026-04)

### 1.1 GTK3 → wry → tao → kullanıcı arayüzü

```
[webkit2gtk-rs hâlâ GTK3]
         ↓
      [wry 0.55] ←────────────────────── ├─ clipboard (WebView clipboard API)
         ↓                               ├─ dialog (native file picker)
      [tao 0.35] ←─── kullanıcımız ───── ├─ tray-icon entegrasyonu
         ↓                               └─ event loop
     [GTK3 ailesi: gtk, gdk, atk, ...]
         ↓
     [RUSTSEC-2024-0411..0420 — 10 advisory, "archived, use gtk4-rs"]
```

**Kilit etki:**
- `tao 0.35`, `wry 0.55`, `tray-icon 0.22` dondurulmuş.
- Alt zincir: `gtk`, `gdk`, `atk`, `gdkwayland-sys`, `gdkx11-sys`, `gtk-sys`, `atk-sys`,
  `gdk-sys`, `gdkx11`, `gtk3-macros`, `gtk-sys` — hepsi arşivlenmiş fakat runtime'da fonksiyonel.
- `proc-macro-error 1.0.4` (glib-macros üzerinden) compile-time only, runtime yüzeyi yok.
- `glib 0.18.5` — `VariantStrIter` unsound ama biz ve `tao`/`wry` kullanmıyor (grep doğrulandı).

**Onay eden:** `deny.toml` [advisories] bölümünde her advisory için gerekçe yorumu mevcut.

**Ne zaman kalkar?**
- `wry 0.60+` GTK4 desteğini ship ettiğinde (upstream milestone'u 2026 ortası hedef; aktif olarak izleniyor).
- Kaldığında: tek PR ile `tao/wry/tray-icon` → son sürüm, transit GTK3 ailesi doğal olarak
  düşer, `deny.toml`'un `[advisories].ignore` listesi boşalır.

### 1.2 windows-core çakışması

```
[wry 0.55] ─── uses ───→ [windows-core eski sürümü]
                              ↕ trait impl çakışması
[hekadrop] ─── uses ───→ [windows 0.61] ← bunu 0.62'ye çıkaramıyoruz
```

**Kilit etki:**
- `windows 0.61` donuk; `windows 0.62+` wry 0.55'in kullandığı windows-core ile trait implementasyon çakışması üretir (Cargo.toml yorumunda dokümante).

**Ne zaman kalkar?**
- `wry 0.56+` windows-core sürümünü yükselttiğinde.
- Veya 1.1 GTK4 geçişinde `wry 0.60+` geldiğinde (aynı PR'da birlikte yükselir).

### 1.3 Diğer bilinçli sabitlemeler

| Crate | Sabit | Sebep | Kalkış koşulu |
|---|---|---|---|
| `rand` | 0.8 | 0.9 major breaking `rand_core` API'si; `p256 0.13` / `hkdf 0.12` 0.8 ekosisteminde | Crypto stack toplu 0.9'a taşınınca tek PR |
| `prost` / `prost-build` | 0.14 | Quick Share wire format'ı 0.14'ta çalışıyor; 0.15 breaking değil ama test regresyon maliyeti | Önümüzdeki minor yükseltmelerde güncellenir |
| `criterion` | 0.8 | Bench-only, breaking yok ama API stabil | Herhangi bir PR'da güncellenebilir |

---

## 2. Serbest/güncel tutulan bağımlılıklar

Aşağıdakiler **her Dependabot/Renovate PR'ında** güncellenir (CI yeşilse direkt merge):

- `tokio`, `tokio-util`, `bytes`, `anyhow`, `thiserror`, `tracing`, `tracing-subscriber`, `tracing-appender`
- `serde`, `serde_json`, `parking_lot`
- `mdns-sd`, `if-addrs`, `base64`, `hex`
- `sha2`, `subtle` (crypto ama API stabil)
- `notify-rust`
- `pretty_assertions`, `tokio-test`

## 3. Crypto bağımlılıklarının özel statüsü

**Öncelik:** crypto crate'leri diğer bağımlılıklardan önce güncellenir. Harici audit
(Q2-Q4 planı) en güncel sürüm üzerinde yapılmalıdır.

| Crate | Sabit | Notu |
|---|---|---|
| `p256` | 0.13 | ECDH + arithmetic; `elliptic-curve 0.13` ile zincirli |
| `hkdf` | 0.12 | SHA-256/512 |
| `hmac` | 0.12 | SHA-256 |
| `aes` | 0.8 | AES-256 block |
| `cbc` | 0.1 | CBC mode; `cipher 0.4` block-padding |
| `cipher` | 0.4 | Block cipher trait katmanı |
| `subtle` | 2 | Constant-time karşılaştırma |
| `elliptic-curve` | 0.13 | P-256 SEC1 encoding |
| `sha2` | 0.10 | SHA-256, SHA-512 |

**Major geçiş** (ör. p256 0.14, hkdf 0.13): **RFC gerektirir** — wire format geri uyumluluğunu
etkileyebilir. RFC template'inde "Güvenlik değerlendirmesi" bölümü zorunludur.

## 4. Supply-chain kuralları

- `cargo-deny` CI'da bloke edici (PR yeşil olmadan merge yok).
- `cargo-audit` haftalık cron; yeni advisory → issue otomatik açılır.
- `cargo-vet` (v0.9.0'dan itibaren): tüm doğrudan bağımlılıklar manuel denetlenmiş olmalı.
- Yeni bir doğrudan bağımlılık eklemek **RFC gerektirir** (`hekadrop-core` için).
  Transit bağımlılıklar otomatik; doğrudan olanlar denetlenir.
- Unknown registry / unknown git reddedilir (`deny.toml` [sources]).

## 5. Yükseltme sırası (prioritized queue)

GTK4 geçişi lock olduğunda, aşağıdaki sırayla yükseltilir:

1. **tao + wry + tray-icon** → son stabil; GTK4 transit zincirini getirir.
2. **windows** → 0.62+ (wry'ın yeni windows-core'uyla uyumlu sürüm).
3. **GTK3 RUSTSEC advisory'leri** `deny.toml`'den temizlenir.
4. `glib 0.18.5` VariantStrIter unsound advisory düşer.
5. `proc-macro-error` zincirden çıkar.
6. Crypto stack'i tek PR'da gözden geçir (major çıkmışsa).
7. `rand` 0.9 geçişi (crypto ile aynı PR).

Her adım ayrı PR, her PR ayrı CHANGELOG girişi.

## 6. Dependency review checklist (PR reviewer için)

Bir dep ekleme/güncelleme PR'ı geldiğinde:

- [ ] `cargo-deny` yeşil (yeni advisory yok veya ignore gerekçeli)
- [ ] CHANGELOG'da `### Changed` veya `### Security` altında satır var
- [ ] Crypto crate'i ise: `docs/security/threat-model.md` "Cryptographic review scope"
      bölümü gözden geçirildi
- [ ] `hekadrop-core` için doğrudan dep ise: RFC referansı var
- [ ] Major bump ise: migration notu `CHANGELOG.md` ve değişen test satırları belirli
- [ ] MSRV (`rust-version = "1.90"`) hâlâ geçerli; dep MSRV yükseltmesi istiyor ise RFC

## 7. 2026-04 snapshot özeti

Cargo.toml'daki durum bu tarihte:
- 26 doğrudan runtime dep (crypto 9, async 3, UI/GUI 3, serialization 3, logging 3, diğer 5)
- 1 build-dep (`prost-build`)
- 3 dev-dep (`pretty_assertions`, `tokio-test`, `criterion`)
- Transit 472 paket (Cargo.lock)
- 11 RUSTSEC advisory suppress (hepsi GTK3 ailesi veya türevleri)
- 0 direct-dep'te RUSTSEC advisory aktif

## 8. Politikanın değişmesi

Bu belge yaşayan bir dokümandır. Değişiklikleri PR ile yap:
- Yeni blokaj zinciri tespit edildiğinde § 1'e ekle.
- Bir blokaj kalktığında § 5'teki adımı tamamlandı işaretle ve ilgili bölümü sadeleştir.
- Crypto stack major update'lerde § 3 tablosunu güncelle.

**Sonraki review:** v0.7.0 release tag'i sonrası (Workspace refactor tamamlandığında
`hekadrop-core` crate'in kendi Cargo.toml'u olacak; crypto stack orada izole edilecek
— revize tetikleyicisi).

---

İlgili dosyalar:
- [`Cargo.toml`](../Cargo.toml) — tek otoritatif sürüm listesi
- [`Cargo.lock`](../Cargo.lock) — transitif lock, vendor doğrulama kaynağı
- [`deny.toml`](../deny.toml) — advisory ignore gerekçeleri
- [`docs/security/threat-model.md`](security/threat-model.md) — crypto dep'leri de kapsayan threat model
