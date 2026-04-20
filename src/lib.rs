//! HekaDrop library surface — yalnız benchmarklar ve harici entegrasyon testleri
//! için public re-export katmanı.
//!
//! Binary `src/main.rs` bu lib'e bağımlı değildir; modül ağacı ikisinde de
//! bağımsızca derlenir (Cargo lib+bin hibrit projeyi bu şekilde ele alır).
//! Buradaki amaç sadece `benches/crypto.rs` gibi harici consumer'lara
//! `hekadrop::crypto` yüzeyini açmaktır.

pub mod crypto;
pub mod file_size_guard;
