//! HekaDrop library surface — yalnız benchmarklar ve harici entegrasyon testleri
//! için public re-export katmanı.
//!
//! Binary `src/main.rs` bu lib'e bağımlı değildir; modül ağacı ikisinde de
//! bağımsızca derlenir (Cargo lib+bin hibrit projeyi bu şekilde ele alır).
//! Buradaki amaç sadece `benches/crypto.rs` gibi harici consumer'lara
//! `hekadrop::crypto` yüzeyini ve H#4 privacy controls testleri için
//! `hekadrop::settings` yüzeyini açmaktır.

pub mod crypto;

// `settings` modülü platform-specific `config_dir`/`logs_dir` path
// çözümlemesi için `platform`'a, legacy bytes redaksiyonu için
// `log_redact`'e ve cihaz adı türetme için `config`'e dayanıyor. Bu üç
// modül de saf yardımcı — `src/main.rs` tarafındaki `RUNTIME`/`tao`
// bağımlılıklarını çekmezler, lib bağlamında sorunsuz derler.
pub mod config;
pub mod log_redact;
pub mod platform;
pub mod settings;
