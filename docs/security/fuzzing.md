# HekaDrop Fuzzing Politikası

Bu döküman HekaDrop'un fuzzing stratejisini, harness envanterini, corpus
yönetimini ve crash triage prosedürünü tanımlar. Operatif kullanım için
`fuzz/README.md` dosyasına bakın; bu doküman **politika** odaklıdır.

## Strateji

Fuzzing, ağ üzerinden gelen her attacker-controlled bayt dizisi için
zorunlu güvenlik ağımızdır. Quick Share protokolü şu yüzeyleri açar:
(1) pre-auth UKEY2 handshake, (2) post-handshake şifreli loop, (3) mDNS
discovery metadata. Bu yüzeylerin **hepsi** için bir fuzz harness'i
yazılmalıdır; aksi halde parse katmanındaki herhangi bir `unwrap()` /
aritmetik taşma / `unreachable!()` pre-auth DoS'a dönüşür.

Q1 scaffold (bu teslimat): 4 temel harness. Q2: + 6 harness ve OSS-Fuzz
entegrasyonu.

## Harness Envanteri

### Q1 — devrede

| Harness | Hedef | Saldırı yüzeyi |
| --- | --- | --- |
| `fuzz_frame_decode` | `OfflineFrame::decode` | Her TCP frame body prost decode |
| `fuzz_payload_header` | `PayloadTransferFrame` decode + accessor walk | PayloadAssembler ingest öncesi |
| `fuzz_ukey2_handshake_init` | `process_client_init(&[u8])` | Pre-auth, attacker ilk temas |
| `fuzz_secure_decrypt` | `SecureCtx::decrypt` (zero-keys) | AES-CBC + HMAC + D2D decode |

### Q2 — planlanan

| Harness | Hedef | Beklenen LoE |
| --- | --- | --- |
| `fuzz_ukey2_handshake_finish` | `process_client_finish` | Commitment + ECDH parse |
| `fuzz_frame_decode_partial` | Length-prefix reader + chunked input | `arbitrary::Unstructured` streaming |
| `fuzz_mdns_txt_parse` | mDNS TXT record parser | `discovery.rs` landing sonrası |
| `fuzz_protobuf_wireshare_frame` | `sharing.nearby.Frame::decode` | Introduction / FileMetadata |
| `fuzz_resume_hint_parse` | Resume hint parser | Q2 feature — kod merge'lenince |
| `fuzz_payload_chunk` | `PayloadChunk` + assembler ingest loop | Async runtime harness gerekiyor |

Q2 harness'leri hedef kod merge olmadan yazılmaz; resume hint özelliği henüz
`src/` altında yok.

## Corpus Politikası

- **Lokasyon:** `fuzz/corpus/<harness>/`. Her harness kendi alt dizinine
  sahiptir.
- **Seed corpus:** Repo içine yalnız `.keep` commit'liyoruz. Gerçek seed'ler
  private artifact bucket'ta (Q2'de kurulacak) veya CI run output'undan
  üretilir.
- **Corpus submit prosedürü:** Bir seed eklemek istiyorsanız PR'da minimize
  edilmiş (`cargo fuzz tmin`) halini koyun; 10 KB üstü girişler reject.
- **OSS-Fuzz mirror:** Q2'de Google OSS-Fuzz entegrasyonu tamamlanınca
  corpus otomatik sync edilecek. Proje adı: `hekadrop` (rezerve edildi,
  ROADMAP Q2 Week 3).

## OSS-Fuzz Entegrasyon Planı (Q2)

1. `projects/hekadrop/project.yaml` + `Dockerfile` + `build.sh` PR'ı.
2. ClusterFuzz job'ı her 4 harness için günlük çalışır.
3. Bulunan bug'lar 90 günlük embargo sonrası public açılır (Google standardı).
4. Disclosure contact: `destek@sourvice.com`.

## Crash Triage Playbook

1. **Reproduce:** `cargo +nightly fuzz run <harness>
   fuzz/artifacts/<harness>/crash-<hash>` ile lokalde tekrarlanabilir
   olduğunu doğrula. Minimize et: `cargo fuzz tmin`.
2. **Sınıflandır:**
   - **Kripto/pre-auth DoS** → **private GitHub Security Advisory** aç
     (bkz. `SECURITY.md`). CVE gerekebilir.
   - **Post-auth panic** → normal issue, `security` + `fuzz-found` etiketi.
   - **Parse-only panic (no memory safety issue)** → normal issue.
3. **Fix PR:** Düzeltme + regression test (`tests/regression/<id>.rs`) aynı
   PR'da. Test crash girdisini hex literal veya `include_bytes!` ile
   sabitlemeli.
4. **Publish:** Advisory CVE ile aç, release notes'a ekle, auto-update
   tetikle. Pre-auth vuln için kullanıcılara upgrade bildirimi UI'da.
5. **Backfill:** Crash corpus'a eklenir, OSS-Fuzz'a push edilir —
   regression'ın tekrar yakalanması garantilenir.

## Sahiplik

- Q1 scaffold: Fuzz Engineer rolü (bu PR).
- Q2 genişletme: Security Eng + Crypto reviewer birlikte.
- OSS-Fuzz başvurusu + onboarding: Security Eng.
