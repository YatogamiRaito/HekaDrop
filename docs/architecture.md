# HekaDrop Architecture (v0.7 post-Foundation)

> **Durum:** RFC-0001 Foundation refactor (Adım 1-8) tamamlandı; bu doküman post-refactor topolojisini, dep akışını ve extension noktalarını anlatır. v1.0.0'a kadar **public API stable değil** — her crate `publish = false`.

## 5 üyeli Cargo workspace

```
                     ┌──────────────────────┐
                     │   hekadrop-proto     │
                     │  (leaf — prost-gen)  │
                     └──────────┬───────────┘
                                │
                                ▼
                     ┌──────────────────────┐
                     │   hekadrop-core      │
                     │  (protocol engine)   │
                     └─────┬───────────┬────┘
                           │           │
                  ┌────────┘           └─────────┐
                  ▼                              ▼
        ┌──────────────────┐         ┌──────────────────┐
        │  hekadrop-net    │         │  hekadrop-cli    │
        │  (mDNS adapter)  │         │   (v0.10 stub)   │
        └────────┬─────────┘         └──────────────────┘
                 │
                 ▼
        ┌──────────────────────────────────────┐
        │            hekadrop-app              │
        │  (binary: tao + wry + tray-icon +    │
        │   platform shims + i18n + state      │
        │   singleton plumbing + UI adapters)  │
        └──────────────────────────────────────┘
```

Tüm kenarlar **tek yönlü** — cyclic dep yok. CI'da `cargo hack check --feature-powerset --no-dev-deps --workspace` her crate'i izole derler; çevrim oluşursa erken yakalanır.

## Crate sorumlulukları

### `hekadrop-proto`
- **İçerik:** `prost-build` ile `proto/*.proto` dosyalarından üretilen wire format tipleri (Quick Share / Nearby Connections).
- **Bağımlılık:** `bytes`, `prost`. Sıfır iş mantığı.
- **Lint disiplini:** generated kod için module-level `#[allow]` (CLAUDE.md I-2 istisnası); el yazımı kod barındırmaz.

### `hekadrop-core` (protocol engine)
- **İçerik:** UKEY2 handshake, AES/HMAC kripto, frame codec, payload assembler, `AppState` plain struct, connection/sender/server protocol mantığı, settings/identity/stats domain tipleri, `UiPort` + `PlatformOps` trait'leri.
- **Garanti:**
  - Sıfır UI bağımlılığı (`tao`, `wry`, `tray-icon` yok).
  - Sıfır global singleton (`OnceLock`, `Lazy` yok — RFC-0001 §9 R2).
  - Sıfır platform shim (`crate::platform::*` yasak — CLAUDE.md I-1).
- **Adapter'lar trait üzerinden:** UI çağrıları `Arc<dyn UiPort>`, platform çağrıları (clipboard, open URL) `Arc<dyn PlatformOps>` parametre olarak gelir.

### `hekadrop-net` (network adapter)
- **İçerik:** `discovery::scan` (mDNS browse), `mdns::*` (advertise / Quick Share servis kayıtları).
- **Bağımlılık:** `mdns-sd` (network I/O), `hekadrop-core` (domain tipleri).
- **Neden ayrı:** mDNS daemon'u headless ortamlarda (CLI/daemon) opsiyonel olabilir; ayrıca CLI/Android wrapper farklı keşif backend'leri kullanabilir.

### `hekadrop-cli` (v0.10.0 stub)
- **İçerik:** Tek `main.rs` — "v0.10.0'da gelecek" basıp çıkar.
- **Niye var:** Workspace topology + build sıralaması doğrulamak. v0.10.0'da `clap` + IPC + send/receive/list-peers/trust/doctor komutlarıyla şişecek.

### `hekadrop-app` (binary + UI)
- **İçerik:** GUI binary (tao + wry), tray-icon, platform shims (windows-rs, dirs), i18n tabloları, `STATE: OnceLock<Arc<AppState>>` singleton plumbing, `UiAdapter` + `PlatformAdapter` impl'leri.
- **Caller olur, callee değil:** İçindeki `i18n`, `paths`, `platform` modüllerine **core dokunamaz** (CLAUDE.md I-1). App, core'a Arc<AppState> + path/closure inject eder.

## Extension noktaları (trait inject pattern)

Core'un app-only modüllere bağımlı kalmaması için, sınır noktalarında **trait + dependency injection** kullanılır.

### `UiPort` (RFC-0001 §5 Adım 5b)

```rust
// hekadrop-core/src/ui_port.rs
#[async_trait::async_trait]
pub trait UiPort: Send + Sync {
    fn notify(&self, n: UiNotification);
    async fn prompt_accept(
        &self,
        device: &str,
        pin: &str,
        files: &[FileSummary],
        text_count: usize,
    ) -> AcceptDecision;
}
```

`UiNotification` enum 4 varyant taşır (`Toast`, `FileReceived`, `ToastRaw`, `TrustMigrationHint`). i18n çevrim **caller-side** — core sadece `&'static str key + Vec<String> args` taşır, app-side `UiAdapter` `crate::i18n::tf(key, &args)` çağırır.

### `PlatformOps` (Adım 5c)

```rust
// hekadrop-core/src/connection.rs (trait), app/src/ui_adapter.rs (impl)
pub trait PlatformOps: Send + Sync {
    fn open_url(&self, url: &str);
    fn copy_to_clipboard(&self, text: &str);
}
```

`PlatformAdapter` (app) trait'i implement ederek `crate::platform::open_url` / `crate::platform::copy_to_clipboard`'ı sarar.

### `AppState` constructor injection

```rust
impl AppState {
    pub fn new(
        settings: Settings,
        identity_path: &Path,
        stats_path: PathBuf,
        config_path: PathBuf,
        default_device_name: String,
        default_download_dir: PathBuf,
    ) -> Arc<Self>
}
```

Path resolution + platform-default değerler **app-side `state::init`'te** bir kez yapılır, AppState bunları taşır. Core içinde `crate::paths::*` veya `crate::platform::*` çağrısı yok.

### `Settings::resolved_device_name` closure injection (Adım 4)

```rust
impl Settings {
    pub fn resolved_device_name<F: FnOnce() -> String>(&self, default: F) -> String;
    pub fn resolved_download_dir<F: FnOnce() -> PathBuf>(&self, default: F) -> PathBuf;
}
```

Caller closure ile platform default'unu inject eder.

## Singleton plumbing — `hekadrop-app` only

`STATE: OnceLock<Arc<AppState>>` ve 11 free-fn shim (`set_listen_port`, `request_*_window`, `consume_*_window`, vs.) yalnız **app crate'inde**. Core tüketicileri (CLI, daemon, FFI, future Android wrapper) kendi state ownership pattern'lerini kullanır — global'a bağımlı değildir.

## Async I/O disiplini

Sync file I/O async fonksiyon içinde **`tokio::task::spawn_blocking` veya `block_in_place` ile sarmalanır** — worker thread bloklanmaz. Pattern (PR #93 review sonrası uygulandı):

- Fire-and-forget (örn. stats save): `spawn_blocking(move || { let _ = snap.save(&path); })`
- Sync return gerektiren (örn. unique_downloads_path): `block_in_place(|| ...)`

`AppState::set_progress_completed_auto_idle` `Handle::try_current()` ile runtime detect eder; tokio dışı caller (CLI, FFI) için panik yerine reset task **skip** edilir.

## Lint disiplini

Workspace-wide `[workspace.lints]` policy (root `Cargo.toml`):

- **Ship-blocker:** `dbg_macro=deny`, `todo`, `unimplemented`, `exit`, `unwrap_used`, `expect_used`, `panic`, `print_stdout/stderr`
- **Numerik safety:** `cast_possible_truncation`, `cast_possible_wrap`, `cast_sign_loss`, `cast_precision_loss`, `cast_lossless`
- **Unsafe disiplini:** `unsafe_op_in_unsafe_fn=deny`, `undocumented_unsafe_blocks`
- **API hygiene:** Embark/uv/ruff konsensus — `rc_mutex`, `mem_forget`, `map_err_ignore`, `redundant_clone`, `use_self`

Her `#[allow]` gerekçeli yorumla belgeli (`// INVARIANT:`, `// SAFETY:`, `// SAFETY-CAST:`, `// API:`). Crate-level `#![allow]` yasak — sadece generated kod istisna.

Test profili relaxation `lib.rs`/`main.rs` `#![cfg_attr(test, allow(...))]` + integration test başlık blokları ile ayrı yönetilir.

Detay: [`CLAUDE.md`](../CLAUDE.md) I-1...I-6 invariants + pre-commit kontrol listesi.

## Supply-chain CI

`.github/workflows/ci.yml` `lints-extra` job (PR #87):
- `cargo machete` — kullanılmayan dep tespiti
- `cargo hack check --feature-powerset --no-dev-deps --workspace` — feature kombinasyonları + her crate izole derleme
- `typos` — codebase yazım denetimi
- `cargo deny check` — lisans + RUSTSEC advisory + wildcard ban (`deny.toml`)

## v0.7 → v1.0.0 yol haritası

| Sürüm | İçerik | Hedef |
|---|---|---|
| v0.7.0 | Foundation refactor (RFC-0001 §1-8 ✓) | mevcut |
| v0.8.0 | Chunk-HMAC + Transfer Resume + Folder Payload (RFC-0003/0004/0005) | sırada |
| v0.9.0 | Fuzzing + harici güvenlik audit | sonra |
| v0.10.0 | `hekadrop-cli` send/receive komutları | sonra |
| v1.0.0 | Public API semver freeze + paket yöneticisi yayınları (Homebrew/Winget/Scoop/Flathub/Snap/AUR/Nixpkgs) | 2028-04-24 |

Detay: [`docs/ROADMAP.md`](ROADMAP.md), [`docs/MILESTONES.md`](MILESTONES.md).
