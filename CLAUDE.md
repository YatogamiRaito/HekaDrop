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
hekadrop-cli      — headless CLI binary (v0.10 deliverable tamamlandı)
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

- **Güncel sürüm:** v0.9.0 (released)
- **Aktif milestone:** v0.9.0 (Fuzzing ve Test Güvenliğinin Olgunlaştırılması)
- **Sıradaki:** cargo-mutants ve proptest entegrasyonları ile test kapsamının güçlendirilmesi
- **MSRV:** Rust 1.90 (CI'da pinned)
- **Edition:** 2021
- **Lint policy:** root `Cargo.toml` `[workspace.lints]` — pedantic batch 1-14 enforce edildi (too_many_lines + large_futures dahil)
- **Commit konvansiyonu:** Türkçe imperative başlık + `Why:` satırı (bkz. CONTRIBUTING.md)
- **AI commit footer:** `Co-Authored-By: Antigravity <noreply@google.com>`

---

## Sıradaki işler (öncelik sırasıyla)

1. **cargo-mutants entegrasyonu** — Kod tabanındaki test kapsamını mutant testleriyle doğrula.
2. **Property-based testing (proptest)** — UKEY2 state transitions ve payload reassembly için özellik tabanlı testler yaz.
3. **afl.rs entegrasyonu** — Alternatif bir fuzzer olarak entegre et.
4. **v0.10.1 daemon altyapısı** — `hekadrop-cli daemon` gerçek kurulabilir sistem/arkaplan servisi implementasyonu.
5. **Static musl binary** — `x86_64-unknown-linux-musl` target ile ~4-6 MiB CLI binary.
6. **NLnet başvurusu** — Ekim 2026 deadline; `docs/security/audit-scope.md` altyapı hazır.
7. **OSS-Fuzz yeniden başvuru** — v0.11.0+ sonrası.

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

Workspace lints `Cargo.toml [workspace.lints]`'te. Pedantic batch 1-14 enforce edildi (toplam ~67 lint). Batch geçmişi git log'unda; burada tutulmaz.

**Kapsam dışı (ertelenmiş):**
- `clippy::similar_names` — crypto test variable naming, risk > kazanç
- `clippy::redundant_pub_crate` — `unreachable_pub` ile çakışıyor, RFC-0001 sonrası

**Tamamlanan ertelenmiş lint'ler (v0.9.0):**
- ~~`clippy::too_many_lines`~~ — yapısal refaktör ile enforce edildi (connection.rs 1747 satır refaktör)
- ~~`clippy::large_futures`~~ — `Box::pin` sarmalı ile enforce edildi (server.rs, main.rs)

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
