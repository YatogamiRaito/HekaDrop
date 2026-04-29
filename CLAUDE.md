# HekaDrop — Claude operasyonel rehberi

Bu dosya Claude'un her oturumda otomatik okuduğu **kuruluş prensipleri + pre-commit kontrol listesi**. Amacı: AI review'cuların (Gemini/Copilot) sonradan yakaladığı sorunları **commit-öncesi** yakalamak.

---

## Workspace mimarisi

5 crate (RFC-0001 Foundation refactor v0.7 — TAMAMLANDI; Adım 1-8 merge oldu):

```
hekadrop-proto    leaf — yalnız prost-üretilmiş wire format tipleri
   ↑
hekadrop-core    protocol engine — kripto, frame, UKEY2, secure, payload,
                   identity, stats, settings, state, connection, sender,
                   server, ui_port (trait + UiNotification enum). UI/i18n/
                   global-state YOK.
   ↑
hekadrop-net     mDNS discovery + advertising. Core buna bağımlı değil; app
                   tarafından orchestrate edilir.
   ↑
hekadrop-cli     headless CLI binary stub.
   ↑
hekadrop-app     binary + UI (tao/wry/tray-icon) + platform shims +
                   state singleton plumbing + i18n + UiPort/PlatformOps
                   trait impl'leri (UiAdapter / PlatformAdapter).
```

App `pub use hekadrop_core::*` shim ile core sembollerini re-export eder; in-tree call site'lar (`crate::crypto::*`, `crate::error::*`) dokunulmadan derlenir.

---

## Established invariants — her commit-öncesi kontrol et

Aşağıdakilerin her biri **mevcut bir patolojiyi yakalamak için** kuruldu. Yeni kod bunları ihlal ediyorsa commit ÖNCESİ yakalamalı (sonradan AI review'cu yakalarsa "process gap" demektir).

### I-1. R2 — Core crate app-only modüllere bağımlı olamaz

Yasak `crate::*` referansları core içinde:
- `crate::platform::*` — Windows/macOS/Linux native shims, app-only (windows-rs, dirs)
- `crate::paths::*` — config/identity/stats yol helper'ları, app-only
- `crate::ui::*` — tao/wry/notify-rust, app-only
- `crate::i18n::*` — translation tables, app-only
- `crate::state::*` (singleton wrapper API'si) — app-only; **plain struct erişimi parametre/Arc ile**

**Çözüm pattern'leri:**
- Path: caller `&Path` argümanı geçer (örn. `Settings::load(&Path)`)
- Default values: caller closure geçer (örn. `resolved_device_name<F: FnOnce() -> String>(default: F)`)
- UI: trait + enum (örn. `UiPort` + `UiNotification` — Adım 5b'de kuruluyor)
- i18n: caller-side translation, core sadece `&'static str key` + `Vec<String> args` payload taşır

**Lint olarak enforce:** workspace.lints `unused_crate_dependencies` false-positive'leri yüzünden yok; **manuel kontrol** zorunlu. Pre-commit grep:
```bash
grep -n 'crate::platform\|crate::paths\|crate::ui\|crate::i18n' crates/hekadrop-core/src/
# 0 sonuç olmalı
```

### I-2. `#[allow(...)]` her zaman scoped + yorumlu

- **Crate-level `#![allow(...)]` YASAK** (tek istisna: `hekadrop-proto` generated module attribute'ları minimal-set).
- **Module-level `#[allow]`** sadece generated kod include'u için.
- **Item-level `#[allow]`** mümkün olan en dar scope (single fn / single statement).
- **Her `#[allow]` gerekçeli yorumla**:
  - `// INVARIANT: ...` — mantıksal değişmez (HKDF len ≤ 8160 vs)
  - `// SAFETY: ...` — unsafe blok için pointer/lifetime/ownership
  - `// HUMAN: ...` — kullanıcı görünür precision loss (byte → MB display)
  - `// API: ...` — public API ergonomic kararı (serde signature kontratı)
  - `// PROTO: ...` — wire format truncation, caller-side bounded
  - `// TODO(#NNN): ...` — tracking issue ile ertelenmiş cleanup

**Test profili relaxation** ayrı: `lib.rs`/`main.rs` `#![cfg_attr(test, allow(...))]` + integration test dosyalarının başında dosya-bazlı `#![allow(...)]`. Bu OK; production lint'leri test idiomatik kullanımı bozmasın diye.

### I-3. `map_err(|_e: T| ...)` → `with_context(|| ...)`

`anyhow::Context::with_context` kullan; orijinal hatayı zincirde koru. `_e` parametre ismi `clippy::map_err_ignore` lint'ini biçimsel susturur ama intent'i bypass eder — yasak.

```rust
// YASAK:
i64::try_from(x).map_err(|_e: TryFromIntError| anyhow!("x çok büyük"))?

// DOĞRU:
i64::try_from(x).with_context(|| format!("x çok büyük: {}", x))?
```

### I-4. Yeni lint eklemek = mevcut codebase'de 0 hit

- 0 hit → direkt ekle, PR aç.
- ≤20 hit → hepsini fix'le, allow ekleme; PR'da hem lint config hem fix.
- >20 hit → ayrı tracking issue + cleanup PR; lint enable için bekle.

Lint set "warn but don't enforce" muğlak alanına KAÇIRILMAMALI — `-D warnings` ile CI kırılır. Workspace.lints (root Cargo.toml) **enforceable**.

### I-5. Untrusted input + aritmetik = checked aritmetik

Peer'den gelen `i64`/`u64`/`usize` değerlerle arithmetic operasyon yapılıyorsa:
- `checked_add` / `checked_mul` / `checked_div` zinciri
- Overflow → `None` / sessiz skip (DoS koruması), `unwrap`/panic değil
- `as u8`/`as u32` cast'i yalnızca `clamp(0, MAX)` veya `try_from().ok()` sonrası

Örnek: `crates/hekadrop-core/src/connection.rs::compute_recv_percent`.

### I-6. Hidden global state core'a sızdırma

Core'da `static`, `OnceLock`, `Lazy`, `lazy_static` **YASAK** (process-level domain singleton). Function-local `static` mutex (sadece I/O serialization) gri bölge — yorumla gerekçele.

App'ta singleton OK (state.rs OnceLock) ama core'a taşırken plain struct + Arc dağıtımı zorunlu.

---

## Pre-commit checklist

Her `git commit` ÖNCESİ:

```bash
# 1. Diff'i fresh oku
git diff --cached

# 2. Established invariants taraması
grep -n 'crate::platform\|crate::paths\|crate::ui\|crate::i18n' crates/hekadrop-core/src/
grep -rn '#!\[allow' crates/hekadrop-core/src/ crates/hekadrop-app/src/  # crate-level allow var mı?
grep -rn 'map_err.*|_e:' crates/  # _e bypass var mı?

# 3. Standard checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo machete --with-metadata
typos
```

Tüm yeşilse commit. Bir tanesi sarı/kırmızıysa fix öncesi commit yok.

### Bilinen gap: platform-gated kod lokal lint kapsamında değil

`cargo clippy --fix` veya manuel taramada lokal host platformu (genelde
macOS) **hangi `#[cfg(target_os = "...")]` blokları derliyorsa onları
görür** — diğer platform'ların gated kodu (Linux GTK / Windows Win32)
kapsam dışıdır. Cross-compile setup pratik değildir (GTK system dep'leri).

**Workaround:** Lint enforce eden bir PR push'unun ilk CI run'unda
Linux + Windows fail edebilir; CI log'larındaki `--> path:line` listesini
manuel fix + push iterasyonu. Bu pattern PR #93, #107 (uninlined_format_args)
ve gelecekteki tüm cross-cutting lint enforce PR'larında **beklenmelidir**;
1 ekstra CI iterasyonu kabul edilebilir maliyet.

İleride elimine etmek için:
- Cross-platform clippy CI matrix step'i + `cargo clippy --fix` koş
  → fix önerisini patch olarak çıkar, lokal apply
- VEYA cross-compile container kur (Docker/devcontainer)

## Pre-push adversarial review (önerilir)

`git push` ÖNCESİ adversarial review agent çağır — özellikle non-trivial PR'larda:

```
Agent: "Bu diff'i `hekadrop-core` boyunca established invariant'lara
karşı incele. Özellikle ara:
1. core'da app-only module referansı (I-1)
2. yorumsuz #[allow] (I-2)
3. lint-bypass map_err pattern (I-3)
4. checked olmayan aritmetik (I-5)
5. hidden global state (I-6)

Diff özeti: [...]
"
```

Agent çıktısını triaj et — gerçek bulgu varsa fix, yanlış pozitif notla.

## AI review pipeline

Her PR otomatik:
- **Gemini code-assist** — yarı detaylı incelemesi, medium-priority comment'ler
- **Copilot pull-request-reviewer** — PR overview + spot comment'ler

Bu yorumları her zaman triaj et:
- Critical/security → aynı PR'a follow-up commit
- Scope-dışı (ayrı abstraction önerisi) → ayrı PR'a notla
- Stale/yanlış → cevap yorumu (henüz uygulanmadı)

---

## Repo bilgisi

- **MSRV:** Rust 1.90 (CI'da pinned)
- **Edition:** 2021
- **Lint policy:** root `Cargo.toml` `[workspace.lints]`
- **Test allow set:** lib.rs/main.rs `#![cfg_attr(test, allow(...))]` + integration test başlık blokları
- **Commit konvansiyonu:** Türkçe imperative başlık + `Why:` satırı (bkz. CONTRIBUTING.md)
- **Footer:** AI commit'lerine `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`

## RFC-0001 Foundation (TAMAMLANDI)

| Adım | Durum | Tamamlandığı PR |
|---|---|---|
| 1 — workspace iskele | ✓ | #85 |
| 2 — hekadrop-proto | ✓ | #86 |
| 3 — hekadrop-core (8 leaf) | ✓ | — |
| 4 — identity/stats/settings/payload → core (R2 inject pattern) | ✓ | — |
| 5a — AppState plain struct + impl | ✓ | — |
| 5b — connection.rs UiPort trait (RFC §9 R1) | ✓ | #92 |
| 5c — state/connection/sender/server → core | ✓ | #93 |
| 6 — hekadrop-net (discovery + mdns) | ✓ | #100 |
| 7 — hekadrop-cli stub | ✓ | #100 |
| 8 — kapanış (lib.rs sil + surface lock) | ✓ | #100 |

Mevcut crate yapısı (`crates/hekadrop-{proto,core,net,cli,app}`) Foundation
hedefini karşılıyor. Aktif iş **RFC-0003** (chunk-HMAC + capabilities exchange)
üzerinde — sender/receiver pipeline entegrasyonu sıradaki adım.

## Deferred strictness sweep'leri (PR #87 body'sinde liste)

Workspace'a eklenmemiş ama eklenmeli lint'ler — ayrı PR serisi:
`clippy::pedantic` (~1,228), `clippy::doc_markdown` (445+792), `unreachable_pub` (349), `uninlined_format_args` (auto-fix yapıldı, lint enable yok), `match_same_arms` (68), `cast_possible_wrap` (36 — security audit gerek), vs.

Enforce edilenler (sweep history):
- `clippy::must_use_candidate` (37 source `#[must_use]` + proto module-level allow generated kod için).
- `clippy::items_after_statements` (7 site fix — const/use/inner-fn yukarı taşındı).
- `clippy::map_unwrap_or` (13 site auto-fix — `.map(f).unwrap_or(d)` → `.map_or(d, f)`).

Refactor (RFC-0001) bittikten sonra strictness sweep'lere dön.
