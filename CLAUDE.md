# HekaDrop — Claude operasyonel rehberi

Bu dosya Claude'un her oturumda otomatik okuduğu **kuruluş prensipleri + pre-commit kontrol listesi**.

---

## Workspace mimarisi

```
hekadrop-proto    — prost-üretilmiş wire format tipleri (leaf)
       ↑
hekadrop-core     — protokol engine: UKEY2, AES-256-CBC, HMAC, frame,
                    payload, chunk-HMAC, resume, folder, connection, sender, server
       ↑
hekadrop-net      — mDNS discovery + advertising
       ↑
hekadrop-cli      — headless CLI stub (v0.10'da gelişecek)
       ↑
hekadrop-app      — binary + UI (tao/wry/tray-icon) + platform shims + i18n
```

App `pub use hekadrop_core::*` shim ile core sembollerini re-export eder.

---

## Established invariants — her commit-öncesi kontrol et

### I-1. Core crate app-only modüllere bağımlı olamaz

Yasak referanslar core içinde: `crate::platform::*`, `crate::paths::*`, `crate::ui::*`, `crate::i18n::*`, `crate::state::*` singleton wrapper'ı.

**Çözüm pattern'leri:** caller `&Path` geçer, caller closure geçer, trait + enum (`UiPort` + `UiNotification`), caller-side translation.

Pre-commit grep:
```bash
grep -n 'crate::platform\|crate::paths\|crate::ui\|crate::i18n' crates/hekadrop-core/src/
# 0 sonuç olmalı
```

### I-2. `#[allow(...)]` her zaman scoped + yorumlu

- **Crate-level `#![allow(...)]` YASAK** (tek istisna: `hekadrop-proto` generated module attribute'ları).
- Her `#[allow]` gerekçeli yorum:
  - `// INVARIANT:` — mantıksal değişmez
  - `// SAFETY:` — unsafe blok
  - `// HUMAN:` — kullanıcı görünür precision loss
  - `// API:` — public API ergonomic kararı
  - `// PROTO:` — wire format truncation
  - `// TODO(#NNN):` — tracking issue ile ertelenmiş cleanup

### I-3. `map_err(|_e: T| ...)` → `with_context(|| ...)`

`anyhow::Context::with_context` kullan; orijinal hatayı zincirde koru.

### I-4. Yeni lint eklemek = mevcut codebase'de 0 hit

0 hit → direkt ekle. ≤20 hit → fix + ekle. >20 hit → ayrı tracking issue.

### I-5. Untrusted input + aritmetik = checked aritmetik

`checked_add` / `checked_mul` / `checked_div`; overflow → `None` / sessiz skip.

### I-6. Hidden global state core'a sızdırma

Core'da `static`, `OnceLock`, `Lazy`, `lazy_static` YASAK.

---

## Pre-commit checklist

```bash
git diff --cached
grep -n 'crate::platform\|crate::paths\|crate::ui\|crate::i18n' crates/hekadrop-core/src/
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo machete --with-metadata
typos
```

---

## Repo bilgisi

- **Güncel sürüm:** v0.8.0
- **Aktif milestone:** v0.9.0 (2026-09-30) — Fuzzing + Audit hazırlık
- **Sıradaki:** v0.10.0 (2026-10-31) — CLI binary + headless daemon
- **MSRV:** Rust 1.90 (CI'da pinned)
- **Edition:** 2021
- **Lint policy:** root `Cargo.toml` `[workspace.lints]` — pedantic batch 1-13 enforce edildi
- **Commit konvansiyonu:** Türkçe imperative başlık + `Why:` satırı (bkz. CONTRIBUTING.md)
- **AI commit footer:** `Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>`

---

## Sıradaki işler (öncelik sırasıyla)

1. **NLnet başvurusu** — Ekim 2026 deadline; `docs/security/audit-scope.md` altyapı hazır.
   Başvuru: https://nlnet.nl/propose/ (Privacy & Trust Enhancing Technologies programı).
2. **ClusterFuzzLite doğrulama** — `.clusterfuzzlite/` eklendi; CI'da gerçekten çalışıyor mu
   kontrol et (workflow tetikle, build + run yeşil mi).
3. **v0.10.0 CLI binary** — `crates/hekadrop-cli` stub'ı; `hekadrop send/receive/list-peers`
   komutları. `docs/ROADMAP.md` §v0.10.0 detaylı spec.
4. **Pedantic batch 14** — `too_many_lines` (connection.rs, sender.rs büyük fn'ler) +
   `large_futures` (async state machine boxing). Her ikisi yapısal refactor; bağımsız PR.
5. **OSS-Fuzz yeniden başvuru** — v0.11.0+ sonrası, daha fazla star/contributor ile.

---

## Tamamlanan RFC'ler

| RFC | Konu | Durum |
|---|---|---|
| RFC-0001 | Workspace refactor (5-crate split) | ✅ v0.8.0 |
| RFC-0003 | Chunk-HMAC + capabilities exchange | ✅ v0.8.0 |
| RFC-0004 | Transfer resume (ResumeHint + PartialMeta) | ✅ v0.8.0 |
| RFC-0005 | Folder payload (HEKABUND container) | ✅ v0.8.0 |

---

## Lint disiplini özeti

Workspace lints `Cargo.toml [workspace.lints]`'te. Pedantic batch 1-13 enforce edildi (toplam ~65 lint). Batch geçmişi git log'unda; burada tutulmaz.

**Kapsam dışı (ertelenmiş):**
- `clippy::too_many_lines` — büyük fonksiyonlar (connection.rs, sender.rs) refactor gerektirir
- `clippy::large_futures` — async state machine boxing, architectural change
- `clippy::similar_names` — crypto test variable naming, risk > kazanç
- `clippy::redundant_pub_crate` — `unreachable_pub` ile çakışıyor, RFC-0001 sonrası

**Bilinen gap:** platform-gated kod (`#[cfg(target_os = "...")]`) lokal lint kapsamı dışı. CI push sonrası Linux/Windows fail edebilir; 1 ekstra iterasyon kabul edilebilir.

---

## AI review pipeline

Her PR otomatik:
- **Gemini code-assist** + **Copilot** — triaj et; critical/security aynı PR'a, scope-dışı ayrı PR'a.

---

## Güvenlik altyapısı (v0.9.0)

- `fuzz/` — 10 cargo-fuzz harness (UKEY2, frame, SecureCtx, chunk-HMAC, vb.)
- `.clusterfuzzlite/` — CI'da PR bazlı + nightly fuzzing
- `oss-fuzz/` — hazır, yeniden başvuru v0.11.0+ sonrası
- `supply-chain/` — cargo-vet (Mozilla import), cargo-auditable release build
- `docs/security/audit-scope.md` — harici audit scope dökümanı
