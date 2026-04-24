# HekaDrop Fuzz Harness'leri

`cargo-fuzz` (libFuzzer) tabanlı fuzz altyapısı. Q1 güvenlik teslimatı
kapsamında scaffold edilmiştir; uzun fuzz koşuları (OSS-Fuzz entegrasyonu +
corpus oluşturma) Q2'dedir. Politika dokümanı: `docs/security/fuzzing.md`.

## Önkoşullar

- **Rust nightly** toolchain (libFuzzer `#![no_main]` + `-Z sanitizer` için şart):
  ```sh
  rustup toolchain install nightly
  ```
- **cargo-fuzz** CLI:
  ```sh
  cargo install cargo-fuzz
  ```
- macOS: Xcode command line tools (libFuzzer linker shim).
- Linux: `clang` (AddressSanitizer desteği için).

## Çalıştırma

Repo kökünden:

```sh
# Sadece build (CI smoke check):
cargo +nightly fuzz build

# Tek bir harness'i çalıştır:
cargo +nightly fuzz run fuzz_ukey2_handshake_init

# Süre sınırı ve worker sayısı:
cargo +nightly fuzz run fuzz_frame_decode -- -max_total_time=300 -workers=4
```

Harness'ler:

| Hedef | Giriş noktası | Not |
| --- | --- | --- |
| `fuzz_frame_decode` | `OfflineFrame::decode` | Prost decoder structural guard |
| `fuzz_payload_header` | `PayloadTransferFrame::decode` + accessor walk | Ingest pipeline panic guard |
| `fuzz_ukey2_handshake_init` | `process_client_init(&[u8])` | Pre-auth saldırı yüzeyi |
| `fuzz_secure_decrypt` | `SecureCtx::decrypt` (zero-keys) | Post-handshake parser |

## Yeni harness ekleme

1. `fuzz/fuzz_targets/fuzz_<isim>.rs` oluştur. Şablon:
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   fuzz_target!(|data: &[u8]| {
       let _ = hekadrop::... (data);
   });
   ```
2. `fuzz/Cargo.toml` içine `[[bin]]` bloğu ekle (`test/doc/bench = false`).
3. Yapılandırılmış giriş gerekiyorsa `arbitrary::Arbitrary` türet:
   ```rust
   #[derive(arbitrary::Arbitrary, Debug)]
   struct Input { key_id: u8, body: Vec<u8> }
   fuzz_target!(|inp: Input| { ... });
   ```

## Corpus

- Seed corpus konumu: `fuzz/corpus/<harness>/` (git'te yalnız `.keep`).
- Harici corpus ekleme prosedürü: `docs/security/fuzzing.md` → **Corpus Policy**.
- CI'da corpus indirilmez; libFuzzer sıfırdan üretir. Q2'de OSS-Fuzz corpus
  mirror'ı devreye girdiğinde bu politika güncellenecek.

## Crash triage

1. Yerel tekrar: `cargo +nightly fuzz run <harness> fuzz/artifacts/<harness>/<crash-file>`
2. Minimize: `cargo +nightly fuzz tmin <harness> fuzz/artifacts/<harness>/<crash-file>`
3. Kripto yolunda bir panik/UB ise **private GitHub Security Advisory** aç
   (bkz. `SECURITY.md`). Aksi halde normal issue yeterli.
4. Fix merge olduktan sonra crash dosyasından regression testi üret:
   `tests/regression/<issue_id>.rs` altında bytes'ı hex literal olarak sakla.

## Notlar

- `src/lib.rs` içinde `process_client_init` yalnız fuzz için re-export edildi
  (`TODO(fuzz/Q1)` yorumlu). Q2'de `hekadrop-core` crate split tamamlandığında
  bu export doğal olarak public API hâline gelecek — o zaman yoruma gerek
  kalmaz.
- `SecureCtx` alanları `pub`; fuzz harness'i struct literal ile inşa eder
  (`new_with_keys` `#[cfg(test)]` olduğundan fuzz crate'inden erişilemez).
- Frame'in I/O katmanı (async `TcpStream` read) fuzz edilmez — tek parse
  etkisi `u32::from_be_bytes` + bounds check; çıktı bytes protobuf decoder'ına
  girer ve `fuzz_frame_decode` orayı kapsar.
