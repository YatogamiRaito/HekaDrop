# RFC 0001 — Workspace Refactor (v0.7.0 "Foundation")

- **RFC numarası:** 0001
- **Başlık:** HekaDrop Cargo Workspace Refactor
- **Yazar:** Architect (destek@sourvice.com)
- **Durum:** Draft — implementation ready
- **Hedef sürüm:** v0.7.0 (2026-06-15)
- **İlgili:** `docs/ROADMAP.md` §Q1 "Foundation", Issue #17 trust race izleri
- **Ön koşul:** branch `feature/v0.7-foundation` açık; MSRV 1.90 (CI'da pinned); Cargo workspace 2021 edition

---

## 1. Motivation (Neden bölüyoruz?)

Bugün HekaDrop tek bir Cargo crate'i: `src/main.rs` **2084 LOC**, `src/lib.rs` **101 LOC** re-export katmanı ve 23 adet kardeş modül (toplam **12 832 LOC**). Lib ve binary aynı modül ağacını iki kere derliyor (`src/lib.rs` içindeki `mod ukey2;` + `src/main.rs` içindeki `mod ukey2;` dual-include). Bu yapı dört somut maliyet üretiyor:

| # | Problem | Kanıt |
|---|---------|-------|
| M1 | **Yeniden kullanılabilir kütüphane yok.** 3rd party (Android router, Rust daemon, FFI wrapper) `tao`/`wry`/`tray-icon` bağımlılığı olmadan protocol engine'i alamaz. | `Cargo.toml:31-33` UI crate'leri tepe seviye `[dependencies]` altında. |
| M2 | **Test sınırları bulanık.** `tests/*.rs` (16 dosya) `hekadrop` crate'i üzerinden lib surface'ine bağımlı; `src/lib.rs:12-101` yalnızca küçük bir altkümeyi `pub` ediyor; genişletmek için lib.rs'yi her seferinde düzenlemek gerekiyor (`src/lib.rs:47-50` "dual-include senkronu" yorumu bu borcu kabul ediyor). |
| M3 | **CLI / daemon / Docker yolu kapalı.** `docs/ROADMAP.md:203` v0.10.0'da `hekadrop-cli`'in "şişmesi" planlı; bugün `tao`/`wry` headless ortamda link olmuyor. |
| M4 | **Build süresi.** Tek crate, tek codegen-unit (`release` profile). `prost-build` (7 .proto) + `tao`+`wry`+`windows` crate'i her modül değişikliğinde tümü yeniden compile. `build.rs` taşınması tahmini app crate için **~%40 daha kısa** incremental build (ROADMAP Q1 §v0.7.0 claim). |

Ayrıca v0.8.0 (Chunk-HMAC + Resume), v0.9.0 (fuzzing) ve v0.10.0 (CLI) iş paketleri bu refactor'un arkasına kuyruklanmış durumda. Bu RFC o kuyruğun önündeki kilidi açar.

---

## 2. Current State Audit — Modül Haritası

Aşağıdaki tablo `grep "^use crate::" src/*.rs` çıktısından türetilmiştir (§ç.ekler). "Hedef crate" kolonu hiçbir spekülasyon içermez — ROADMAP §Q1 v0.7.0'daki isimlerle birebir eşleşir.

| Dosya | LOC | Kendi crate:: bağımlılıkları | Dış önemli bağ. | Hedef crate |
|-------|----:|------------------------------|-----------------|-------------|
| `error.rs` | 161 | — | `thiserror` | **core** (pub) |
| `crypto.rs` | 248 | — | `aes`, `cbc`, `hmac`, `hkdf`, `sha2`, `p256` | **core** (pub) |
| `frame.rs` | 50 | `error` | `tokio::io`, `bytes` | **core** (pub) |
| `ukey2.rs` | 594 | `crypto`, `error`, `frame`, `securegcm`, `securemessage` | `p256`, `prost` | **core** (pub) |
| `secure.rs` | 224 | `crypto`, `error`, `securegcm`, `securemessage` | `prost`, `hmac` | **core** (pub) |
| `payload.rs` | 876 | `error`, `location::nearby::connections::*` | `sha2`, `std::fs` | **core** (pub) |
| `file_size_guard.rs` | 100 | — | — | **core** (pub) |
| `log_redact.rs` | 130 | — | `tracing` | **core** (pub) |
| `identity.rs` | 329 | — | `p256`, `serde` | **core** (pub) |
| `connection.rs` | 1633 | `error`, `frame`, `payload`, `secure`, `state`, `ui`, `ukey2`, `location::*`, `sharing::*` | `tokio::net` | **core** (state/ui coupling KIRILACAK — §9) |
| `sender.rs` | 1037 | `config`, `connection`, `discovery`, `error`, `frame`, `payload`, `secure`, `state`, `ukey2`, `location::*`, `sharing::*` | `tokio::net` | **core** |
| `server.rs` | 84 | `connection` | `tokio::net` | **core** |
| `state.rs` | 401 | `identity`, `settings`, `stats` | `parking_lot`, `tokio_util` | **core** (pub, ama §4'e bkz) |
| `stats.rs` | 124 | — | `serde` | **core** (pub) |
| `settings.rs` | 1758 | `error` | `serde_json` | **core** (pub) — büyük ama self-contained |
| `config.rs` | 66 | — | `serde` | **core** (pub) |
| `discovery.rs` | 128 | `config` | — | **net** |
| `mdns.rs` | 92 | `config` | `mdns-sd` | **net** |
| `i18n.rs` | 778 | — | `serde_json` | **app** |
| `platform.rs` | 733 | — | `windows`, `#[cfg]`'li | **app** |
| `ui.rs` | 1101 | — | `tao`, `wry`, `tray-icon`, `notify-rust` | **app** |
| `main.rs` | 2084 | tümü | `tao`, `wry`, `tray-icon` | **app** |
| `lib.rs` | 101 | (test re-exports) | — | **silinir** (core/app kendi lib.rs'ını yazar) |

Üretilen protobuf modülleri (`securegcm`, `securemessage`, `location.nearby.*`, `sharing.nearby`) bugün `src/lib.rs:31-87` ve `src/main.rs:49-101` içinde **iki kez** `include!` ediliyor — bu bir teknik borç işareti (lib/bin dual-include); refactor bunu atomik olarak kapatır.

### 2.1 Kritik Coupling Tespitleri

1. **`connection.rs:30` → `use crate::ui;`** ve `connection.rs` içinde 18 adet `ui::` kullanımı. `sender.rs` ve `server.rs`'de `ui::` yok → core → ui bağımlılığı yalnız connection'da. **Kırılmalı:** connection handler'ı `Fn(UiEvent)` callback/broadcast channel alır (bkz. §9 R1).
2. **`state.rs`** → `identity`, `settings`, `stats` çekirdek tiplerini tek `AppState` altında toplar. Bu bir core tipidir (UI bağımlısız), AMA `state::get()` singleton pattern'ı **OnceLock global**. Core'da global singleton **kabul edilmez** (library contract). **Kırılmalı:** core crate `AppState::new()` döner; singleton instantiation `hekadrop-app/src/main.rs`'de kalır.
3. **`settings.rs`** ve `i18n.rs` — birincisi self-contained core, ikincisi yalnız UI renderer'ları kullanır → `i18n` app'e ait.
4. **`platform.rs`** — `#[cfg(target_os = "...")]` ile platform spesifik clipboard/registry/notify. UI'dan çağrılır → app.

---

## 3. Target Crate Graph

```
                   +------------------+
                   |  hekadrop-proto  |   (leaf: yalnız build.rs + prost çıktıları)
                   +------------------+
                             ^
                             | (generated types)
                             |
                   +------------------+
                   |  hekadrop-core   |   (no_std-dostu değil; std + tokio)
                   | protocol engine  |
                   +------------------+
                     ^              ^
                     |              |
                     |              +-------------------+
                     |                                  |
           +-----------------+                +------------------+
           |  hekadrop-net   |                |  hekadrop-cli    |
           | transport adap. |                | (stub, v0.7→v0.10|
           +-----------------+                |  boyutu 20 LOC)  |
                     ^                        +------------------+
                     |                                  ^
                     |                                  |
                     |     +---------------------+      |
                     +-----|   hekadrop-app      |------+
                           | tao/wry/tray + i18n |
                           +---------------------+
```

**Yön kuralları:**
- `proto` hiçbir workspace üyesine bağlanamaz (leaf).
- `core` yalnız `proto`'ya bağlıdır (+ tokio/std crates).
- `net` yalnız `core` + `proto`'ya bağlıdır. `tao`/`wry`/`tray-icon` link etmez.
- `app` her üçüne bağlanabilir.
- `cli` `core` + `net`'e bağlanır; `app`'e **asla**.
- Ters kenar (örn. `core → app`) cycle'dır ve CI'da `cargo-deny` tarafından reddedilir (§7).

---

## 4. Public API Surface — `hekadrop-core`

Semver taahhüdü **v0.1.0'da başlar** (HekaDrop uygulama versiyonu v0.7.0 olsa da kütüphane yeni bir paket; `cargo publish --dry-run` KPI'ı ROADMAP:161'da). MSRV **1.90** (workspace `rust-version` anahtarında pin), CI matrix'i 1.90 + stable.

### 4.1 `pub` Yüzey (semver-lı)

```rust
// hekadrop-core/src/lib.rs
pub mod crypto;              // HKDF, AES-CBC, HMAC-SHA256 primitifleri
pub mod error;               // HekaError enum (+ From impls)
pub mod frame;               // wire frame read/write + HANDSHAKE_READ_TIMEOUT
pub mod ukey2;               // handshake + DerivedKeys + validate_server_init
pub mod secure;              // SecureCtx encrypt/decrypt
pub mod payload;             // PayloadAssembler + CompletedPayload
pub mod file_size_guard;     // guard helpers
pub mod identity;            // DeviceIdentity (load/generate/sign)
pub mod settings;            // Settings (serde-backed)
pub mod stats;               // Stats counters
pub mod log_redact;          // log redaction filters
pub mod config;              // compile-time constants

pub mod connection;          // pub fn handle(...) + ConnectionEvents
pub mod sender;              // pub async fn send_files(...)
pub mod server;              // pub async fn accept_loop(...)

pub mod state {              // AppState type — instantiation caller'da
    pub struct AppState { /* builder pattern */ }
    pub struct TransferGuard { /* ... */ }
    // OnceLock'lu global YOKTUR. `AppState` `Arc<AppState>` olarak taşınır.
}

// prost çıktıları — hekadrop-proto'dan re-export (tek yol)
pub use hekadrop_proto::{securegcm, securemessage, location, sharing};
```

### 4.2 `pub(crate)` veya Private

- `connection.rs`'deki helper parser'lar (`parse_remote_name` vb.) `pub(crate)`.
- `payload::block_in_place_if_multi` private.
- `ukey2::` içindeki `fn build_server_init` vb. private; yalnız `client_handshake`/`server_handshake` + `validate_server_init` pub.

### 4.3 Hangi Tip ASLA pub Değil

- `ui::` call-back'leri, `tray_icon::Menu` vb. GUI crate'lerinden gelen her şey.
- `tao::window::Window` → core asla bu tipi taşımaz; UI event'i `enum ConnectionEvent` ile app'e verilir.

### 4.4 Feature'lar (§6'ya bkz)

- `fuzzing` — `PayloadAssembler` constructor'larına ekstra visibility.
- `benches` — kripto primitif'lerinin inline'ını açar.
- Default: `["std"]` (tokio zorunlu; bugün `no_std` hedefi yok — ROADMAP.md'de belirtilmediği için scope dışı).

---

## 5. Migration Plan — Incremental PR Serisi

Her adım **< 4 saat** iş, **ayrı PR**, `cargo test --workspace` yeşil kalmak zorunda. "Binary davranışı birebir aynı" success criteria (§10) her PR'da kapı olarak uygulanır.

### Adım 1 — Workspace iskele (PR #A)
- Root `Cargo.toml` `[package]` → `[workspace]` dönüştürülür:
  ```toml
  [workspace]
  resolver = "2"
  members = ["crates/hekadrop-app"]
  [workspace.package]
  version = "0.7.0"
  edition = "2021"
  rust-version = "1.90"
  ```
- Mevcut `src/`, `build.rs`, `proto/`, `tests/`, `benches/`, `fuzz/` **git mv** ile `crates/hekadrop-app/` altına. Kaynak yol değişikliği dışında hiçbir satır kodunu düzenleme.
- Crate adı `hekadrop` kalır (binary ismi `hekadrop`). `Cargo.lock` aynı hash üretir → regression yok.
- **Çıktı:** `cargo build` ve `cargo test` geçer; tek crate'li workspace.

### Adım 2 — `hekadrop-proto` (PR #B)
- `crates/hekadrop-proto/` üyesi yaratılır: `Cargo.toml`, `build.rs` (bugünkü `build.rs:1-25` aynen kopyalanır), `src/lib.rs` prost-include'ları barındırır (§1 M2'deki dual-include borçu ilk kez TEKİL olur).
- `crates/hekadrop-app/src/lib.rs` ve `main.rs`'daki `include!(concat!(env!("OUT_DIR"), ...))` blokları `pub use hekadrop_proto::*` ile değiştirilir.
- `proto/` dizini app'ten proto crate'ine taşınır.
- **KPI'ya sinyal:** bu adımdan sonra `cargo doc -p hekadrop-proto` çalışır.

### Adım 3 — Pure-crypto `hekadrop-core` iskelesi (PR #C)
- `crates/hekadrop-core/` yaratılır. **Taşınacak ilk set:** `crypto.rs`, `secure.rs`, `frame.rs`, `ukey2.rs`, `error.rs`, `file_size_guard.rs`, `log_redact.rs`, `config.rs`. Hepsi kendi içinde yaprak; app tarafında `pub use hekadrop_core::*` ile eşitleme.
- `hekadrop-app` geçici olarak `features = ["core-shim"]` ile çift yol destekler (güvenlik ağı); adım 6'da shim düşer.

### Adım 4 — `identity`, `stats`, `settings`, `payload` (PR #D)
- Self-contained tipler core'a taşınır. `settings.rs` **1758 LOC** büyük ama tek dış bağı `error` → risksiz.
- `payload.rs`'deki `location::nearby::connections::...` path'i artık `hekadrop_proto::` üzerinden çözülür.

### Adım 5 — `state` + `connection`/`sender`/`server` → core (PR #E, EN RİSKLİ)
- `state.rs`'deki `OnceLock<AppState>` singleton app'e çıkar. Core içinde `AppState` plain struct döner; `Arc<AppState>` parametre olarak gezer.
- `connection.rs:30` `use crate::ui;` **silinir**; `ConnectionEvent` enum'u eklenir (`Progress`, `Completed`, `Error`, `PinToShow`, vb.); handler `tokio::sync::mpsc::UnboundedSender<ConnectionEvent>` alır. App tarafında `ui.rs` bu kanal üzerinden render eder.
- `server::accept_loop`, `sender::send_files` imza değişiklikleri callsite'ları yalnız `hekadrop-app/src/main.rs`'de mevcut.
- Bu PR boyunca `tests/trust_hijack.rs`, `tests/cancel_per_transfer.rs` gibi stateful testler core'la birlikte taşınır.

### Adım 6 — `hekadrop-net` (PR #F)
- `discovery.rs`, `mdns.rs` → `crates/hekadrop-net/`. Bugün `config`'e bağlı; config core'a taşındığı için `net → core` kenarı temiz.
- `mdns-sd` bağımlılığı yalnız net'e taşınır; core Cargo.toml'undan düşer → core'un bağımlılık ayak izi küçülür (ROADMAP v0.8.0 için önkoşul).

### Adım 7 — `hekadrop-cli` stub (PR #G)
```rust
// crates/hekadrop-cli/src/main.rs
fn main() { println!("HekaDrop CLI v0 — coming in v0.10.0"); }
```
`Cargo.toml` → `hekadrop-core` + `hekadrop-net` bağımlılıklı; henüz hiçbiri kullanılmıyor ama ileri-bağlantı kontrolü için tutulur (dead-code warn'lar `#![allow(unused_imports)]` ile bastırılır).

### Adım 8 — Kapanış (PR #H)
- `crates/hekadrop-app/src/lib.rs` silinir (re-export artık gereksiz).
- `crates/hekadrop-app/src/main.rs` küçülür: ana modül ağacı yerine `use hekadrop_core::*; use hekadrop_net::*;`.
- README'deki "Building" bölümü `cargo build --workspace` ile güncellenir.
- `CHANGELOG.md` 0.7.0 kalemi: "workspace refactor; lib `hekadrop-core` v0.1.0 yayıma hazır".

### 5.1 Adımların Zamanlama Tablosu

| PR | Başlık | Tahmini saat | Regresyon riski |
|----|--------|-------------:|-----------------|
| #A | Workspace iskele | 2h | Düşük |
| #B | proto crate | 3h | Düşük |
| #C | Pure-crypto core | 3h | Düşük |
| #D | identity/stats/settings/payload core | 4h | Orta |
| #E | state + connection/sender/server (API break) | 4h | Yüksek |
| #F | net crate | 2h | Düşük |
| #G | cli stub | 1h | Yok |
| #H | cleanup | 2h | Düşük |

Toplam ~21 saat; 3 haftada eşit dağıtılabilir.

---

## 6. Feature Flags Stratejisi

| Flag | Tanımlı yer | Etki | Propagation |
|------|-------------|------|-------------|
| `core/fuzzing` | `hekadrop-core/Cargo.toml` | `PayloadAssembler::new_for_fuzz`, `SecureCtx::from_raw_keys` gibi test-only constructor'ları `pub` yapar. | `fuzz/Cargo.toml` → `hekadrop-core = { path = "../crates/hekadrop-core", features = ["fuzzing"] }` |
| `core/benches` | aynı | Kripto primitif'lerinde `#[inline(never)]` tercihleri geriletir (apples-to-apples bench). | `benches/` ayrı crate olur: `hekadrop-benches`, `[features] default = ["hekadrop-core/benches"]`. |
| `app/gtk3-legacy` | `hekadrop-app/Cargo.toml` | `tao` GTK3 backend'i (Ubuntu 22.04 fallback). | app-internal; diğer crate'lere görünmez. |
| `app/core-shim` | aynı | Adım 3-5 arası geçici uyumluluk shim'i. **Adım 8'de silinir.** | |

**Kural:** `default-features = false` daima desteklenir; `[workspace.dependencies]` bölümünde her üyenin feature'ları açık belirtilir, implicit on değil.

---

## 7. Dependency Flow Kuralları (Encoded Lint)

`cargo-deny` konfigürasyonuna (`deny.toml`) şu bölüm eklenir:

```toml
[bans]
# Cycle / katman ihlallerini banla. `forbidden-by` listesi önce, sonra pozitif kural.
deny = [
    # hekadrop-core dependency graphında hekadrop-app görünürse fail:
    { crate = "hekadrop-app", wrappers = ["hekadrop-core"] },
    { crate = "hekadrop-app", wrappers = ["hekadrop-net"] },
    { crate = "hekadrop-app", wrappers = ["hekadrop-cli"] },
    { crate = "hekadrop-net", wrappers = ["hekadrop-app"] },
    { crate = "hekadrop-core", wrappers = ["hekadrop-net"] },
    { crate = "tao", wrappers = ["hekadrop-core", "hekadrop-net", "hekadrop-cli"] },
    { crate = "wry", wrappers = ["hekadrop-core", "hekadrop-net", "hekadrop-cli"] },
    { crate = "tray-icon", wrappers = ["hekadrop-core", "hekadrop-net", "hekadrop-cli"] },
]
```

CI: mevcut `deny.toml` adımına ek olarak `cargo deny --workspace check bans` PR-blocking koşulur. Ek koruma: `.github/workflows/ci.yml` matrix'ine `cargo tree -p hekadrop-core --no-default-features | grep -E "^(tao|wry|tray-icon)"` grep'i eklenir — match çıktısı hata olur.

---

## 8. Testing Continuity

Mevcut 16 integration test dosyası ve bunların hedef crate'i:

| Test | LOC etki | Hedef crate |
|------|---------|-------------|
| `frame_codec.rs`, `frame_limits.rs` | frame | core |
| `hmac_tag_length.rs`, `secure_roundtrip.rs` | secure/crypto | core |
| `ukey2_handshake.rs`, `ukey2_downgrade.rs` | ukey2 | core |
| `payload_corrupt.rs`, `file_metadata_size_guard.rs` | payload | core |
| `cancel_per_transfer.rs`, `trust_hijack.rs` | state + connection | core |
| `rate_limiter.rs`, `server_rate_limiter.rs` | server/state | core |
| `save_non_blocking.rs` | payload disk I/O | core |
| `legacy_ttl.rs`, `settings_migration.rs`, `privacy_controls.rs` | settings | core |
| `mdns_discovery.rs` | discovery/mdns | **net** |

**Migrasyon kuralı:** bir test, refactor ettiği modülle aynı PR'da core/net crate'ine taşınır. `tests/common/` yardımcıları core ile taşınır; app'e özgü test-helper'ı henüz yok. `cargo test --workspace --all-features` KPI'a dönüşür (ROADMAP §Q1).

`benches/crypto.rs` → adım 8'de `hekadrop-core/benches/crypto.rs` olur; `[[bench]]` tanımı core crate'ine gider.

`fuzz/fuzz_targets/` → `hekadrop-core = { path = "../../crates/hekadrop-core", features = ["fuzzing"] }`; `cargo-fuzz` workspace-aware değildir ama `fuzz/Cargo.toml` üye listesine alınmaz (`[workspace] exclude = ["fuzz"]`), cargo-fuzz konvansiyonu.

---

## 9. Risks & Mitigations

| # | Risk | Olasılık | Etki | Azaltma |
|---|------|---------|-----|---------|
| R1 | `connection.rs:30` (`use crate::ui`) core'dan çıkıp event channel'ına dönüşürken UI render'ı başka thread/yaşam döngüsüne kayar; tray kısa donmalar yaşayabilir. | Orta | Orta | Event payload'ı `Clone + Send + 'static`; `mpsc::unbounded_channel` başlangıçta (backpressure gerekmiyor — yalnız UI değil `tracing` da consumer). `tests/cancel_per_transfer.rs` gate. |
| R2 | Protobuf import yolu değişimi: bugün `crate::location::nearby::connections::...`; yarın `hekadrop_proto::location::nearby::connections::...`. | Yüksek | Düşük | `hekadrop-core/src/lib.rs` içinde `pub use hekadrop_proto::location; pub use hekadrop_proto::sharing; pub use hekadrop_proto::securegcm; pub use hekadrop_proto::securemessage;` → core içinden görünürlük değişmez. App da `hekadrop_core::location::...` şeklinde okur (tek yol). |
| R3 | `#[cfg(target_os = "...")]` platform kodu `platform.rs:733` ve `main.rs`'de dağınık. Windows `windows = "0.61"` crate'i versiyon kilidiyle (wry 0.55 uyumu) sadece app'te kalmalı. | Yüksek | Orta | `hekadrop-app/Cargo.toml`'e sınırlı; `[target.'cfg(windows)'.dependencies]` aynen taşınır. `notify-rust` da app'te kalır (core/net'te kullanılmıyor, grep doğruladı). |
| R4 | `OnceLock<AppState>` singleton'ını söktükçe `state::get()` çağrı sayısı (grep: connection/sender/state/ui'da ~50+ referans) değişiklik ister. | Yüksek | Orta | Geçici adım: core'a `AppState` taşınırken `state::set_global(Arc<AppState>)` + `state::get() -> Arc<AppState>` API'ı korunur ama singleton INSTANTIATION'ı app'e çıkar. Core'u kullanan 3rd party bu API'a girmek zorunda değil (constructor ve `Arc` doğrudan kullanılabilir). |
| R5 | Test flake'leri — mevcut tokio runtime flavor'ı (`src/payload.rs:42-54`) incelendi; workspace değişikliği runtime flavor varsayımını değiştirmemeli. | Düşük | Orta | `#[tokio::test(flavor = "multi_thread")]` başlıkları korunur; test file'ları bire bir taşınır. |
| R6 | `cargo publish --dry-run hekadrop-core` "repo dışı path dependency" uyarısı. | Orta | Düşük | `hekadrop-proto` kendi ayrı crate olarak `crates.io`'ya gider (önce); core sonra. İkisinin de `version = "0.1.0"` publisher'a sabit. |
| R7 | `CHANGELOG.md`, `docs/ROADMAP.md`, `README.md`, `Makefile`'daki `src/` path referansları. | Orta | Düşük | Adım 1 sonu grep script'i (`scripts/post-refactor-path-check.sh`) ile zorunlu güncelleme. |
| R8 | `scoop/`, `Casks/` paketleme recipe'ları binary path varsayımı (`target/release/hekadrop`). | Düşük | Düşük | Workspace default target dizini aynı (`target/release/hekadrop`). Binary adını `hekadrop-app` crate'inde `[[bin]] name = "hekadrop"` ile sabitliyoruz. |

---

## 10. Success Criteria

Refactor'un "tamamlandı" olduğunun yegâne tanımı, aşağıdakilerin hepsi yeşilken PR #H'nin main'e merge edilmesidir:

1. **Build:** `cargo build --workspace --all-features` ve `cargo build --workspace --release` her üç platformda (macOS / Linux / Windows) yeşil.
2. **Test:** `cargo test --workspace --all-features` — 16 integration + varsa yeni unit testler yeşil; ekleme/silme yok.
3. **Bench:** `cargo bench -p hekadrop-core` (veya `-p hekadrop-benches`) `benches/crypto.rs` baseline'ına göre ±%5 tolerans içinde.
4. **Binary:** `target/release/hekadrop` checksum dışında **davranışsal olarak identik** — smoke senaryosu (`docs/design/smoke.md` veya Issue #17 repro set): Android → HekaDrop dosya alımı, HekaDrop → Android text gönderim, history, notification.
5. **Docs:** `cargo doc -p hekadrop-core --no-deps` uyarısız; `hekadrop-core/README.md` minimum başlangıç örneği + lisans ibaresi.
6. **Publish dry-run:** `cargo publish --dry-run -p hekadrop-proto` ve ardından `-p hekadrop-core` başarılı (KPI ROADMAP:161).
7. **Lint:** `cargo deny --workspace check bans` yeşil (§7).
8. **Binary boyutu:** release build artışı %5'i aşmaz (rastlantısal generic-instance patlamasına karşı ölçülür).
9. **MSRV:** `cargo +1.90.0 build --workspace` geçer (CI matrix).

---

## Ekler

### A. Referans Dosya Yolları (absolute)
- `/Users/ebubekirkaraca/Desktop/test/HekaDrop/Cargo.toml` — bugünkü monolit manifesto
- `/Users/ebubekirkaraca/Desktop/test/HekaDrop/src/lib.rs` — dual-include katmanı (silinecek)
- `/Users/ebubekirkaraca/Desktop/test/HekaDrop/src/main.rs` — 2084 LOC binary entry
- `/Users/ebubekirkaraca/Desktop/test/HekaDrop/build.rs` — proto codegen (hekadrop-proto'ya taşınır)
- `/Users/ebubekirkaraca/Desktop/test/HekaDrop/docs/ROADMAP.md:100-112` — v0.7.0 hedef tanımı (normatif)
- `/Users/ebubekirkaraca/Desktop/test/HekaDrop/deny.toml` — §7 için genişletilecek

### B. Açık Sorular (implementation'da kararlaşacak, RFC kapsamı dışı)
- `AppState`'in `Clone`'u mu yoksa `Arc<AppState>`'in mi yaygınlaştırılacağı. (Öneri: ikincisi.)
- `ConnectionEvent` enum'unun `serde::Serialize` olup olmayacağı (v0.10.0 JSON-RPC daemon yüzeyi için).
- `hekadrop-proto` ileride elle yazılmış builder API'lerini mi yoksa yalnız ham prost tiplerini mi expose edeceği. (Öneri: v0.7.0'da yalnız ham; builder'lar v0.8.0+.)

### C. Onay Kapısı
Bu RFC'ye commit edilmiş `Approved-by:` imzası gerektirir (Architect + 1 code owner). Onay sonrası branch `feature/v0.7-foundation` üzerine PR #A açılır; sıralı merge zorunludur (§5 table).
