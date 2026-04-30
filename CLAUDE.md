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
`clippy::pedantic` (~1,228 — kademeli batch'ler enable ediliyor), `clippy::doc_markdown` (445+792), `cast_possible_wrap` (36 — security audit gerek), vs.

Enforce edilenler (sweep history):
- `unreachable_pub` (PR #107: RFC-0001 workspace refactor sonrası 349 → 58 → 0 hit; `pub` → `pub(crate)` indirgemesi + workspace.lints.rust enforce. Bugün 0 hit + 0 allow ile temiz).
- `clippy::uninlined_format_args` (PR #87 auto-fix + sonradan biriken 110 site PR'da tekrar auto-fix + workspace.lints enforce).
- `clippy::must_use_candidate` (37 source `#[must_use]` + proto module-level allow generated kod için).
- `clippy::items_after_statements` (7 site fix — const/use/inner-fn yukarı taşındı).
- `clippy::map_unwrap_or` (13 site auto-fix — `.map(f).unwrap_or(d)` → `.map_or(d, f)`).
- `clippy::match_same_arms` (Cargo.toml'da `warn`; kod auto-fix sonrası 0 hit; 4 item-level scoped allow yorumla — connection.rs `compute_recv_percent` doc-arm + i18n.rs translation tabloları forward-compat için).
- **pedantic batch 1** (PR `chore/lint-pedantic-batch-1`: 5 lint, **hepsi 0 hit** mevcut codebase'de — direkt enforce, fix gerekmedi; kademeli pedantic enable stratejisinin ilk batch'i):
  - `clippy::redundant_else` (0 hit) — `if { return } else {}` redundant else.
  - `clippy::if_not_else` (0 hit) — `if !cond { a } else { b }` → pozitif form.
  - `clippy::single_char_pattern` (0 hit) — `.split("a")` → `.split('a')`.
  - `clippy::inefficient_to_string` (0 hit) — `&T: Display` üzerinde `.to_string()`.
  - `clippy::needless_late_init` (0 hit) — declaration-time init.
- **pedantic batch 2** (PR `chore/lint-pedantic-batch-2`: 5 lint, 17 hit `cargo clippy --fix` auto-fix; 0 allow; davranış-koruyucu mikro temizlik):
  - `clippy::redundant_closure_for_method_calls` (16 hit auto-fix) — `|x| x.foo()` → `Foo::foo` (`Bytes::len`, `Result::ok`, `IpAddr::is_ipv4`, `DirEntry::file_name`, `PoisonError::into_inner`, `str::trim`, `VecDeque::len`, `TrustedDevice::display`).
  - `clippy::cloned_instead_of_copied` (0 hit) — `.cloned()` Copy type üzerinde → `.copied()`.
  - `clippy::manual_string_new` (0 hit) — `String::from("")` → `String::new()`.
  - `clippy::unnested_or_patterns` (1 hit auto-fix) — `Err(A) | Err(B)` → `Err(A | B)` (`folder/sanitize.rs`).
  - `clippy::flat_map_option` (0 hit) — `.flat_map(Option)` → `.filter_map`.
- **pedantic batch 3** (PR `chore/lint-pedantic-batch-3`: 5 lint, 5 hit `cargo clippy --fix` auto-fix; 0 allow; düşük-risk auto-fix mikro temizlik):
  - `clippy::semicolon_if_nothing_returned` (5 hit auto-fix) — `crates/hekadrop-app/benches/crypto.rs` criterion `b.iter(|| ...)` trailing satırlarına `;` eklendi; fn `()` döndüğünde son statement `;` ile sonlanır.
  - `clippy::stable_sort_primitive` (0 hit) — primitive slice `.sort()` → `.sort_unstable()`.
  - `clippy::checked_conversions` (0 hit) — `i32 as u32` overflow-aware `try_from` alternatif.
  - `clippy::ptr_as_ptr` (0 hit) — `*const T as *const U` → `.cast()`.
  - `clippy::ref_option_ref` (0 hit) — `&Option<&T>` redundant indirection.
- **pedantic batch 4** (PR `chore/lint-pedantic-batch-4`: 5 lint, 3 hit manuel fix; 0 allow; control-flow + iterator + collection idiom temizliği):
  - `clippy::implicit_clone` (0 hit) — Clone tipinde `.to_owned()` → `.clone()`; intent netliği.
  - `clippy::map_flatten` (0 hit) — `.map(...).flatten()` → `.flat_map(...)`; tek pass.
  - `clippy::needless_continue` (3 hit manuel fix) — `crates/hekadrop-core/src/folder/sanitize.rs` (1) + `crates/hekadrop-core/src/settings.rs` (2 site: `backup_corrupt_file` retry loop + `atomic_write_mode` tmp open loop). Match arm sonu `=> continue` → `=> {}`; loop akışı zaten devam ediyor.
  - `clippy::manual_assert` (0 hit) — `if !cond { panic!(...) }` → `assert!(cond, ...)`; idiomatic.
  - `clippy::range_minus_one` (0 hit) — `0..(n-1)` → `0..=(n-2)`; inclusive range netliği.
- **pedantic batch 5** (PR `chore/lint-pedantic-batch-5`: 5 lint, 1 hit manuel fix + 0 allow; cast / option / iterator / import idiom temizliği. `cast_lossless` zaten v0.7.x numerik güvenlik bloğunda enforce edili — batch 5 "konsept set" üyesi sayılır, lint config'e ikinci kez eklenmedi):
  - `clippy::cast_lossless` (zaten enforce, 0 hit) — `i32 as i64` → `i64::from(x)`; sıfır-maliyet, intent netliği.
  - `clippy::option_option` (0 hit) — `Option<Option<T>>` antipattern; tristate için custom enum tercih.
  - `clippy::naive_bytecount` (0 hit) — `bytes.iter().filter(|&&b| b == X).count()` → `bytecount` crate; ekstra dep gerekmedi (0 hit, yüksek-volüm byte tarama yok).
  - `clippy::needless_collect` (1 hit manuel fix) — `crates/hekadrop-app/tests/folder_sender_send.rs` `let dirs: Vec<_> = ...filter(...).collect(); dirs.len()` → `let dir_count = ...filter(...).count()`; ara Vec allocation gereksiz.
  - `clippy::wildcard_imports` (0 hit) — `use foo::*;` → explicit import. Test modüllerindeki `use super::*;` ve `pub use ...::*` re-export pattern'ları clippy default exempt.
- **pedantic batch 6** (PR `chore/lint-pedantic-batch-6`: 5 lint, 1 hit manuel fix + 1 scoped allow + 3 zero-hit lint enable; string-builder + struct + return-type idiom temizliği):
  - `clippy::format_push_string` (1 hit manuel fix) — `crates/hekadrop-app/src/main.rs::js_string` ctrl-char escape `out.push_str(&format!("\\u{:04X}", c as u32))` → `let _ = write!(out, "\\u{:04X}", c as u32)` (`std::fmt::Write` trait import); ekstra `String` allocation eliminate.
  - `clippy::manual_str_repeat` (0 hit) — `(0..n).map(|_| s).collect::<String>()` → `s.repeat(n)`; idiomatic + tek allocation. (Önerilen lint adı `manual_string_repeat` clippy 1.92'de mevcut değil; gerçek ad `manual_str_repeat`.)
  - `clippy::unnecessary_box_returns` (0 hit) — `fn f() -> Box<T>` → `fn f() -> T`; ekstra heap indirection gereksizse direkt by-value döndür.
  - `clippy::struct_excessive_bools` (1 hit scoped allow) — `crates/hekadrop-core/src/settings.rs::Settings` 5 bool field (`auto_accept` / `advertise` / `keep_stats` / `disable_update_check` / `first_launch_completed`). Her biri bağımsız user preference; flag enum / bitfield refactor'u serde JSON wire format'ı kıracağı için (mevcut `config.json` migration tabanı) item-level `#[allow(clippy::struct_excessive_bools)]` + API gerekçesi.
  - `clippy::large_types_passed_by_value` (0 hit) — büyük (>256 byte) type by-value parametre → `&T`; gereksiz move/copy.
- **pedantic batch 7** (PR `chore/lint-pedantic-batch-7`: 5 lint değerlendirildi; 4 enforce (1 manuel fix + 3 zero-hit) + 1 KAPSAM-DIŞI; argüman / pointer / visibility / binding / string idiom temizliği):
  - `clippy::needless_pass_by_ref_mut` (0 hit) — `&mut T` argüman gerçekten mutate edilmiyorsa `&T`; immutability disiplini.
  - `clippy::ref_as_ptr` (0 hit) — `&x as *const T` → `std::ptr::from_ref(&x)`; pointer cast idiom (Rust 1.76+).
  - `clippy::no_effect_underscore_binding` (1 hit manuel fix) — `crates/hekadrop-core/src/settings.rs::v06_reject_path_legacy_upgrade_yapmaz` test'inde `let _peer_hash = [0xCC; 6];` no-op binding (eski kodun ne yaptığını dökümante etmek için). Yorum bloğuna dönüştürüldü; `0xCC` literal aşağıdaki assertion'da zaten var (`is_trusted_by_hash(&[0xCC; 6])`).
  - `clippy::needless_raw_string_hashes` (0 hit) — `r#"..."#` raw string'de gereksiz `#` (string'de `"` yoksa); idiomatic.
  - `clippy::redundant_pub_crate` (58 hit, **KAPSAM-DIŞI**) — `hekadrop-app` `lib.rs + main.rs` hibrit crate; `i18n/paths/platform/state/ui/ui_adapter` modülleri yalnız `main.rs`'in private modül ağacında ve `pub(crate)` kullanıyor. Auto-fix `pub`'a çevirmek istiyor — fakat workspace zaten `unreachable_pub = "warn"` enforce ediyor; bu lint aynı item'ları tam tersi yönde (`pub` → `pub(crate)`) raporlar. İki lint **uzlaşmaz**: `redundant_pub_crate` enforce etmek için `unreachable_pub` invariant'ını gevşetmek gerekir. RFC-0001 sonrası `app` crate yeniden yapılandırılırken (örn. salt-binary `bin/`) yeniden değerlendirilecek.
- **pedantic batch 8** (PR `chore/lint-pedantic-batch-8`: 5 lint, 4 zero-hit el yazımı kod + 1 generated-only allow; iterator / variant / call / derive / binding idiom temizliği):
  - `clippy::iter_without_into_iter` (0 hit) — type `iter()` metoduna sahip ama `IntoIterator` impl etmemiş; for-loop ergonomi tutarsızlığı.
  - `clippy::manual_is_variant_and` (0 hit) — `.map_or(false, |x| x.foo())` → `.is_some_and(|x| x.foo())`; intent netliği.
  - `clippy::or_fun_call` (0 hit) — `.unwrap_or(expensive())` → `.unwrap_or_else(|| ...)`; pahalı default lazy hesaplanır.
  - `clippy::derive_partial_eq_without_eq` (6 hit, hepsi prost-üretilmiş `OUT_DIR` modüllerinde — `securegcm.rs:705`, `sharing.nearby.rs:424/647/747`) — `crates/hekadrop-proto/src/lib.rs` her generated `pub mod` allow listesine eklendi (PROTO istisnası, I-2). El yazımı kod 0 hit; gelecekte `PartialEq` derive eden yeni source tip `Eq` da derive etmeli (float field yoksa).
  - `clippy::ref_binding_to_reference` (0 hit) — `if let Some(ref x) = &y` → `if let Some(x) = &y`; `&y` üzerinde `ref` redundant.
- **pedantic batch 9** (PR `chore/lint-pedantic-batch-9`: 5 lint, 14 hit auto-fix + 4 zero-hit lint enable + 0 allow; iterator / literal / option / block / docs idiom temizliği):
  - `clippy::filter_map_next` (0 hit) — `.filter(p).next()` → `.find(p)`; intent netliği + tek pass.
  - `clippy::char_lit_as_u8` (0 hit) — `'a' as u8` → `b'a'`; byte literal idiom.
  - `clippy::manual_ok_or` (0 hit) — `match x { Some(v) => Ok(v), None => Err(e) }` → `x.ok_or(e)`; idiomatic.
  - `clippy::semicolon_outside_block` (14 hit auto-fix) — `{ stmt; }` tek-statement bloklar `{ stmt; };` formuna alındı (block expression + outer `;`). Etki alanı: `crates/hekadrop-app/src/main.rs` (2 cfg-gated `eprintln!` blokları), `crates/hekadrop-app/tests/resume_e2e.rs` (7 scope-drop / set_var / sync_all bloku), `crates/hekadrop-app/tests/folder_chunk_hmac_resume.rs` (2), `crates/hekadrop-app/tests/resume_meta_persist.rs` (1), `crates/hekadrop-core/src/connection.rs` (1 test setup), `crates/hekadrop-core/src/payload.rs` (1 borrow scope). NOT: bu lint `clippy::semicolon_if_nothing_returned` (batch 3) ile etkileşir — auto-fix önce `{ stmt; }` → `{ stmt };` çevirir, sonra inner statement'a tekrar `;` ekler; final form `{ stmt; };` her iki lint'i de tatmin eder.
  - `clippy::doc_link_with_quotes` (0 hit) — rustdoc link içinde gereksiz `"..."` quotes — direkt `[name]` referans.
- **pedantic batch 10** (PR `chore/lint-pedantic-batch-10`: 5 lint, 6 hit auto-fix + 1 hit manuel fix + 3 zero-hit lint enable + 0 allow; bool / late-init / hasher / duplicate-cond / ptr-cast idiom temizliği):
  - `clippy::if_then_some_else_none` (6 hit auto-fix) — `if cond { Some(x) } else { None }` → `cond.then(|| x)` (lazy closure — equivalent semantics; `Some` arm yan etki içermediği için `then_some` yerine `then(||)` auto-fix tercih ettiği fonksiyon-call form). Etki alanı: `crates/hekadrop-core/src/connection.rs` (3 site: stats `keep` snapshot gate × 2 + `RESUME_V1` capability gated `session_id_i64` türetme), `crates/hekadrop-core/src/sender.rs` (2 site: `send` / `send_text` stats `keep` snapshot gate), `crates/hekadrop-app/tests/resume_e2e.rs` (1 site: `RESUME_V1` capability inactive test'inde session_id_used `Option<i64>` türetme).
  - `clippy::useless_let_if_seq` (0 hit) — `let mut x = a; if cond { x = b }` → `let x = if cond { b } else { a }`; declaration-time init.
  - `clippy::implicit_hasher` (1 hit manuel fix) — `crates/hekadrop-core/src/resume.rs::cleanup_sweep` `in_use: &HashSet<(i64, i64)>` parametresi `<S: ::std::hash::BuildHasher>` generic'e alındı (`&HashSet<(i64, i64), S>`). Tüm in-tree caller `HashSet::new()` (default `RandomState`) geçtiği için backward-compatible (S inferred); custom hasher passing artık mümkün — public API genişlemesi geriye dönük uyumlu.
  - `clippy::same_functions_in_if_condition` (0 hit) — `if foo() && foo()` aynı pure fn iki defa çağrılır → değer cache'lenmeli; davranış-kritik (yan etki / cost duplikasyonu).
  - `clippy::transmute_ptr_to_ptr` (0 hit) — `transmute::<*const T, *const U>(p)` → `p.cast::<U>()`; safe pointer-cast idiom (unsafe boundary'yi daraltır).
- **missing_errors_doc** — `hekadrop-core` scope-limited (PR `chore/lint-missing-errors-doc-core`: pedantic umbrella `clippy::missing_errors_doc` yalnız core crate için `#![warn(...)]` lib.rs-level enable. 46 unique pub fn'e `# Errors` doc bloğu eklendi (chunk_hmac × 3, crypto × 1, frame × 3, identity × 1, secure × 2, stats × 2, ukey2 × 4, connection × 1, sender × 2, server × 2, payload × 5, resume × 5, settings × 4, folder/{bundle, enumerate, extract, manifest, sanitize} × 9). Workspace-wide skip — app/net/cli/proto kapsam dışı. Doc-only, no behavior change. CI `-D warnings` ile fiili enforce.).
- **pedantic batch 11** (PR `chore/lint-pedantic-batch-11`: 5 lint, **hepsi 0 hit** mevcut codebase'de — direkt enforce, fix gerekmedi; doctest / dependency / extension / docs / test-panic idiom temizliği):
  - `clippy::needless_doctest_main` (0 hit) — doctest'te `fn main()` redundant; rustdoc otomatik wrap'ler. (Proje doctest yoğun değil.)
  - `clippy::wildcard_dependencies` (0 hit) — `Cargo.toml` `version = "*"` → semver pinning; supply-chain hijyeni. Workspace deps zaten explicit version.
  - `clippy::case_sensitive_file_extension_comparisons` (0 hit) — `Path::ends_with(".png")` case mismatch bug. NOT: `crates/hekadrop-core/src/settings.rs::1806/1841` `OsStr::to_string_lossy().ends_with(".tmp")` ve `tests/mdns_discovery.rs::98` `str.ends_with("._tcp.local.")` lint kapsamı dışı (lint yalnız ASCII letter içeren single-dot extension literal'ı arar).
  - `clippy::doc_lazy_continuation` (0 hit) — markdown list item continuation indentation tutarsızlığı.
  - `clippy::should_panic_without_expect` (0 hit) — `#[should_panic]` payload eksik → `#[should_panic(expected = "...")]`; testin doğru paniği yakaladığını garanti eder.
- **missing_panics_doc** — `hekadrop-core` scope-limited (PR `chore/lint-missing-panics-doc-core`: pedantic umbrella `clippy::missing_panics_doc` yalnız core crate için `#![warn(...)]` lib.rs-level enable; `missing_errors_doc` ile aynı attribute içine virgülle eklendi. 8 unique pub fn'e `# Panics` doc bloğu eklendi (chunk_hmac::compute_tag, crypto::hkdf_sha256, crypto::hmac_sha256, folder/bundle::Bundle::decode, folder/manifest::Manifest::attachment_hash_i64, sender::send, sender::send_text, state::AppState::new). Hepsi pratik olarak panik etmeyen `expect`/`try_into` invariant unwrap'leri (HMAC/HKDF spec, fixed-size slice, `max(0)` invariant) — istisna `AppState::new` identity startup panik (Issue #17 kasıtlı SECURITY tasarımı). Workspace-wide skip — app/net/cli/proto kapsam dışı. Doc-only, no behavior change. CI `-D warnings` ile fiili enforce.).
- **missing_errors_doc + missing_panics_doc — hekadrop-net scope-limited** (PR #173: PR #171 + #172'nin küçük kardeşi. `crates/hekadrop-net/src/lib.rs`'e `#![warn(clippy::missing_errors_doc, clippy::missing_panics_doc)]` source-level enable + crate-level scope yorumu. Toplam 2 hit (her ikisi `missing_errors_doc`; `missing_panics_doc` 0 hit): `discovery::scan` + `mdns::advertise`. Doc-only, no behavior change.).
- **missing_errors_doc + missing_panics_doc — hekadrop-app scope-limited** (PR `chore/lint-missing-docs-app`: lib.rs + main.rs ayrı compilation unit olduğu için her ikisine `#![warn(...)]` eklendi. **0 hit** — app'in pub yüzeyi ezici çoğunlukla `pub use hekadrop_core::*` re-export'u (re-export'lar lint kapsamı dışı; doc core'da). main.rs içindeki `mod i18n/paths/platform/state/ui/ui_adapter` private; tests/ + benches/ içinde `pub fn` yok. Lint enable gelecek-koruyucu — yeni gerçek `pub fn` eklenirse doc zorunlu (CI `-D warnings` blok). Cli/proto hâlâ kapsam dışı.).
- **missing_docs_in_private_items — hekadrop-core scope-limited** (PR `chore/lint-missing-docs-private-core`: pedantic umbrella `clippy::missing_docs_in_private_items` yalnız core crate için `#![warn(...)]` lib.rs-level enable; `missing_errors_doc` + `missing_panics_doc` ile aynı attribute içine virgülle eklendi. 105 hit (1 outside core: `proto/build.rs`) → 0 hit (1-3 satırlık practical doc bloğu ile dokümante: struct field, fn, const, type alias, enum variant — chunk_hmac/config/crypto/frame/identity/negotiation/stats/ukey2/state/resume/settings/folder{bundle,enumerate,extract}/payload/sender/connection). v0.8.0 release prep — internal API surface tam dokümante; yeni private item eklendiğinde CI `-D warnings` blok. Workspace-wide skip — app/net/cli/proto kapsam dışı. Doc-only, no behavior change.).

Refactor (RFC-0001) bittikten sonra strictness sweep'lere dön.
