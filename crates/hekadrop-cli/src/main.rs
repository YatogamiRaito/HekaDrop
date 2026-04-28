//! `HekaDrop` CLI — v0.7'de yalnız stub. v0.10.0'da `send`, `receive`,
//! `daemon`, `list-peers`, `trust`, `doctor`, `version`, `gui` komutları
//! ile şişecek (ROADMAP §Q1 v0.10.0).
//!
//! Şu an bu binary "coming soon" yazıp çıkar — workspace topology'sinin
//! core+net'e erişilebilirliğini doğrulamanın yanı sıra v0.10'a kadar
//! release pipeline'ında hayalet artifact üretmesi engellenir
//! (`publish = false`, `[[bin]] hekadrop-cli`).
//!
//! RFC-0001 §5 Adım 7 (PR #G).

// hekadrop-core + hekadrop-net path-dep olarak çekilse de v0.7 stub'ında
// hiçbir sembol kullanılmıyor — `cargo machete` false-pozitif önlenmiş
// (ignore listesi `Cargo.toml`'da). v0.10.0'da kaldırılacak.
#![allow(unused_imports)]

// CLI binary stdout output legitimate use case; workspace-wide
// `clippy::print_stdout = "warn"` (PR #87 Tier 1) UI/library kodu için
// konuldu. v0.10.0'da clap subcommand layer + structured output (--json
// flag) gelince bu allow kaldırılır.
#[allow(clippy::print_stdout)]
fn main() {
    println!("HekaDrop CLI v0 — coming in v0.10.0");
    println!("Şimdilik GUI tarafını kullanın: `hekadrop` (workspace binary).");
}
