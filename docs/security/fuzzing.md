# HekaDrop Fuzzing Politikası

Bu döküman HekaDrop'un fuzzing stratejisini, harness envanterini, corpus
yönetimini ve crash triage prosedürünü tanımlar. Operatif kullanım için
`fuzz/README.md` dosyasına bakın; bu doküman **politika** odaklıdır.

## Strateji

Fuzzing, ağ üzerinden gelen her attacker-controlled bayt dizisi için
zorunlu güvenlik ağımızdır. Quick Share protokolü şu yüzeyleri açar:
(1) pre-auth UKEY2 handshake, (2) post-handshake şifreli loop, (3) mDNS
discovery metadata, (4) chunk-HMAC ve resume protokol uzantıları.
Bu yüzeylerin **hepsi** için bir fuzz harness'i yazılmalıdır; aksi halde
parse katmanındaki herhangi bir `unwrap()` / aritmetik taşma /
`unreachable!()` pre-auth DoS'a dönüşür.

## Harness Envanteri

### v0.9.0 — 10 harness, `fuzz/fuzz_targets/`

| Harness | Hedef | Saldırı yüzeyi |
| --- | --- | --- |
| `fuzz_ukey2_client_init` | `ukey2::process_client_init(&[u8])` | Pre-auth, attacker ilk temas (P-256 + HKDF) |
| `fuzz_ukey2_client_finish` | `ukey2::process_client_finish(&[u8], &state)` | ECDH commitment verify, anahtar türetme |
| `fuzz_frame_decode` | `frame::dispatch_frame_body` + `OfflineFrame` + `HekaDropFrame` decode | Her TCP frame body magic dispatch + prost |
| `fuzz_secure_decrypt` | `SecureCtx::decrypt(arbitrary_ciphertext)` | AES-256-CBC + HMAC-SHA256 + D2D decode |
| `fuzz_payload_header` | `PayloadTransferFrame` + `PayloadHeader` + `PayloadChunk` decode | PayloadAssembler ingest öncesi |
| `fuzz_payload_assembler` | `PayloadAssembler::ingest(decoded_frame)` | Async assembler state machine |
| `fuzz_chunk_hmac` | `compute_tag` + `verify_tag` + mutated-body rejection | RFC-0003 chunk-HMAC kritik yol |
| `fuzz_resume_meta` | `resume::session_id_i64` + `meta_filename` | RFC-0004 resume meta hesaplama |
| `fuzz_protobuf_frames` | `HekaDropFrame` / `ChunkIntegrity` / `ResumeHint` / `FolderManifest` | Tüm hekadrop_ext tip ailesi |
| `fuzz_endpoint_info` | mDNS endpoint_info bitmap + device name parse | Discovery parse giriş noktası |

### v0.9.x — planlanan genişleme

| Harness | Hedef | Beklenen LoE |
| --- | --- | --- |
| `fuzz_ukey2_full_exchange` | Tam UKEY2 round-trip (mock socket) | `arbitrary::Unstructured` streaming |
| `fuzz_connection_state_machine` | Connection state machine fuzz with HekaDropFrame injection | Çok adımlı stateful harness |
| `fuzz_folder_manifest_parse` | `Manifest::decode` + `Bundle::decode` | RFC-0005 HEKABUND format |
| `fuzz_resume_hint_wire` | `ResumeHint` wire round-trip + `PartialMeta` load | Tempfile-backed harness |

### ClusterFuzzLite (aktif plan)

OSS-Fuzz ile aynı libFuzzer/AFL altyapısı, GitHub Actions CI'da çalışır.
Google onayı gerekmez — PR bazlı veya nightly schedule ile tetiklenir.

- Entegrasyon: `.clusterfuzzlite/Dockerfile` + `build.sh` (mevcut
  `oss-fuzz/` dosyalarından türetilecek).
- Her PR'da 5 dakikalık kısa run; her gece tam run.
- Crash artifact'ları GitHub Actions'ta saklanır.
- Hedef: v0.9.0 — `fuzz.yml` workflow'una entegre.

### oss-fuzz (ertelenmiş)

- PR #15514 "proje henüz yeterince olgun değil" gerekçesiyle kapatıldı
  (criticality score: 0.17 — OSS-Fuzz eşiği ~0.6+).
- `oss-fuzz/` dosyaları depoda korunuyor — yeniden başvuru için hazır.
- Yeniden başvuru: v0.11.0+ sonrası, daha yüksek star/contributor sayısıyla.
- Disclosure contact: `destek@sourvice.com`.

## Corpus Politikası

- **Lokasyon:** `fuzz/corpus/<harness>/`. Her harness kendi alt dizinine sahip.
- **Seed corpus:** Manuel olarak anlamlı `seed_*` dosyaları commit edilir
  (10 KB üst sınır). Fuzzer'in ürettiği SHA-adlı dosyalar `.gitignore`'da —
  repo şişmesini önler.
- **Corpus büyütme:** `cargo +nightly fuzz run <harness>` ile lokal çalıştır;
  `cargo fuzz cmin` ile küçült, `cargo fuzz tmin` ile ilginç girdileri
  minimize et.
- **CI corpus:** Her `fuzz` label'lı PR'da 300s run sonucu `fuzz/artifacts/`
  GitHub Action artifact olarak saklanır (14 gün); anlamlıysa minimize +
  manual seed PR'ı açılır.

## Çalıştırma

```bash
# Nightly gerekli
rustup toolchain install nightly

# Tek target, 60 saniye
cargo +nightly fuzz run fuzz_ukey2_client_init -- -max_total_time=60

# Tüm target'lar derleme testi
cargo +nightly fuzz build

# Crash reproduce
cargo +nightly fuzz run fuzz_ukey2_client_init fuzz/artifacts/fuzz_ukey2_client_init/crash-<hash>

# Corpus minimize
cargo +nightly fuzz cmin fuzz_frame_decode
```

## Crash Triage Playbook

1. **Reproduce:** `cargo +nightly fuzz run <harness> fuzz/artifacts/<harness>/crash-<hash>` ile
   lokalde tekrarlanabilir olduğunu doğrula. Minimize et: `cargo fuzz tmin`.
2. **Sınıflandır:**
   - **Kripto/pre-auth DoS** → **private GitHub Security Advisory** aç
     (bkz. `SECURITY.md`). CVE gerekebilir.
   - **Post-auth panic** → normal issue, `security` + `fuzz-found` etiketi.
   - **Parse-only panic (no memory safety issue)** → normal issue.
3. **Fix PR:** Düzeltme + regression test (`tests/regression/<id>.rs`) aynı PR'da.
   Test crash girdisini hex literal veya `include_bytes!` ile sabitlemeli.
4. **Publish:** Advisory CVE ile aç, release notes'a ekle, auto-update tetikle.
   Pre-auth vuln için kullanıcılara upgrade bildirimi UI'da.
5. **Backfill:** Crash corpus'a eklenir, OSS-Fuzz'a push edilir —
   regression'ın tekrar yakalanması garantilenir.

## Sahiplik

- v0.9.0 scaffold (10 harness): maintainer.
- OSS-Fuzz başvurusu: v0.9.x (Q3 2026 hedef).
- Corpus büyütme + yeni harness: her protocol RFC ile birlikte.
