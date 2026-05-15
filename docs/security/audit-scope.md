# HekaDrop Security Audit Scope

**Belge sürümü:** v0.1
**Tarih:** 2026-05-15
**Kapsanan sürüm:** v0.8.0 (workspace `crates/hekadrop-{proto,core,net,cli,app}`)
**Hedef kitle:** Harici kripto audit ekipleri (Trail of Bits, Cure53, NCC Group,
Least Authority), NLnet grant reviewer'ları, dahili güvenlik reviewer'ları.

Bu belge bir harici güvenlik auditinin **kapsamını** tanımlar. Implementation
detayları `docs/security/threat-model.md`'de, fuzzing politikası
`docs/security/fuzzing.md`'de.

---

## 1. Genel Bakış

HekaDrop, Google Quick Share (Nearby Share) protokolünün Rust ile yazılmış
cross-platform implementasyonudur. Stok Android cihazlardan uygulama
kurmadan LAN üzerinden macOS/Linux/Windows'a dosya/metin/URL aktarır.

**Workspace (v0.8.0):**
```
hekadrop-proto    — prost-generated wire format tipleri
hekadrop-core     — protokol engine: kripto, frame, UKEY2, secure, payload,
                    identity, stats, settings, state, connection, sender, server
hekadrop-net      — mDNS discovery + advertising
hekadrop-cli      — headless CLI stub (minimal)
hekadrop-app      — binary + UI (tao/wry/tray-icon) + platform shims
```

**Audit kritiklik sırası (en kritikten):**
1. UKEY2 anahtar türetme ve handshake (`hekadrop-core/src/ukey2.rs`)
2. Secure channel (AES-256-CBC + HMAC-SHA256) (`hekadrop-core/src/secure.rs`)
3. Kripto primitifler (`hekadrop-core/src/crypto.rs`)
4. Chunk-HMAC pipeline (RFC-0003) (`hekadrop-core/src/chunk_hmac.rs`)
5. Trust store ve paired-key (`hekadrop-core/src/identity.rs`, `settings.rs`)
6. Payload assembly ve path traversal korumaları
7. Rate limiting ve server accept loop

---

## 2. Kritik Bileşenler

### 2.1 UKEY2 Handshake — Yüksek Öncelik

**Dosya:** `crates/hekadrop-core/src/ukey2.rs`

**Kapsam:**
- `process_client_init(client_init_frame: &[u8]) -> Result<ServerInitResult>`
  — raw bytes'tan `Ukey2Message` decode, `Ukey2ClientInit` parse, cipher
  commitment validation, P-256 ephemeral key generate, `Ukey2ServerInit` build.
- `process_client_finish(raw_frame: &[u8], state: &ServerInitResult) -> Result<DerivedKeys>`
  — ECDH key agreement (P-256 `diffie_hellman`), HKDF-SHA256 4-key türetme
  (`encrypt`, `decrypt`, `send_hmac`, `recv_hmac`, `auth_key`, `next_secret`),
  PIN kodu üretimi.
- `validate_server_init(s: &Ukey2ServerInit) -> Result<()>` — client-side
  (ileride).

**Audit odak noktaları:**
- P-256 ECDH: `p256` crate kullanımı, ephemeral anahtar üretimi (OsRng),
  point validation (small subgroup attack mitigation).
- HKDF-SHA256 label'ları ve info yapıları: `"UKEY2 v1 auth"`,
  `"UKEY2 v1 next"`, D2D salt, `"client"` / `"server"` bilgileri.
- Cipher commitment binding: `Ukey2ClientInit.cipher_commitment` vs
  `Ukey2ServerInit.server_init` hash — binding garantisi.
- Timing: commitment comparison sabit-zaman mı?
- Protokol downgrade: `ServerInitResult.cipher_commitment` sadece tek
  commitment mı yoksa birden fazla mı kabul ediyor?

### 2.2 Secure Channel — Yüksek Öncelik

**Dosya:** `crates/hekadrop-core/src/secure.rs`

**Kapsam:**
- `SecureCtx::encrypt(inner_plaintext: &[u8]) -> Result<Vec<u8>>` — AES-256-CBC
  + random IV + HMAC-SHA256 (Encrypt-then-MAC) + D2D seq counter.
- `SecureCtx::decrypt(frame_bytes: &[u8]) -> Result<Bytes>` — HMAC verify,
  IV length check, AES decrypt, D2D seq consistency.

**Audit odak noktaları:**
- **Encrypt-then-MAC sırası:** `HeaderAndBody` encode → HMAC → `SecureMessage`
  sırası doğru mu?
- **IV rastgeleliği:** `rand::thread_rng().fill_bytes(&mut iv)` — OsRng
  tabanlı mı, CSPRNG mi?
- **HMAC tag length kontrolü:** `if smsg.signature.len() != 32` — HMAC
  truncation oracle engelleme.
- **Sabit-zaman HMAC karşılaştırması:** `crypto::hmac_sha256_verify` →
  `subtle::ConstantTimeEq` kullanımı (`crypto.rs:L90`).
- **Sequence counter:** `i32` overflow → `HekaError::SeqOverflow` checked_add;
  seq mismatch rejection.
- **IV reuse:** Her şifreleme çağrısında fresh random IV; IV'ün `d2d_bytes`'a
  bağlanması.

### 2.3 Kripto Primitifler — Yüksek Öncelik

**Dosya:** `crates/hekadrop-core/src/crypto.rs`

**Kapsam:**
- `aes256_cbc_encrypt(key, iv, plaintext) -> Vec<u8>`
  — PKCS7 padding + `cbc::Encryptor<aes::Aes256>`.
- `aes256_cbc_decrypt(key, iv, ciphertext) -> Result<Vec<u8>>`
  — `cbc::Decryptor<aes::Aes256>` + UnpadError propagation.
- `hmac_sha256(key, data) -> [u8; 32]` — `hmac::Hmac<sha2::Sha256>`.
- `hmac_sha256_verify(key, data, expected) -> bool` — `subtle::ConstantTimeEq`.
- `hkdf_sha256(input, salt, info, length) -> Vec<u8>` — `hkdf::Hkdf<sha2::Sha256>`;
  max length = 8160 bytes (HKDF 255 × 32) ile bounded.
- `pin_code_from_auth_key(auth_key: &[u8]) -> String` — auth_key → SHA-512 →
  4 decimal digits.

**Audit odak noktaları:**
- RustCrypto crate versiyonları (`aes` 0.8, `cbc` 0.1, `hmac` 0.12, `hkdf` 0.12,
  `sha2` 0.10, `p256` 0.13) — bilinen zafiyetler?
- `hmac_sha256_verify` sabit-zaman garantisi — `subtle` crate kullanımı yeterli mi?
- `hkdf_sha256` length sınırı (8160) ihlalinde `expect` → `#[allow(clippy::expect_used)]`
  ile bounded; invariant yorum "HKDF max output ≤ 8160 bytes" — geçerli mi?
- AES-CBC padding oracle: `UnpadError` herhangi bir timing sızıntısı var mı?

### 2.4 Chunk-HMAC Pipeline — Orta-Yüksek Öncelik

**Dosya:** `crates/hekadrop-core/src/chunk_hmac.rs`

**Kapsam:** RFC-0003 — her chunk için ayrı HMAC-SHA256 tag (storage corruption
+ in-transit integrity). UKEY2 `next_secret`'ten HKDF-SHA256 ile key türetme
(`"hekadrop chunk-hmac v1"` label).

**Audit odak noktaları:**
- `derive_chunk_hmac_key(next_secret: &[u8]) -> [u8; 32]` — HKDF label benzersizliği.
- `compute_tag(key, payload_id, chunk_index, offset, body) -> Result<[u8; TAG_LEN], ChunkBuildError>`
  — canonical encoding: `payload_id ‖ chunk_index ‖ offset ‖ body_len ‖ body`
  (LE i64 + LE u32 + body). Reordering / truncation attack vektörü?
- `verify_tag(key, expected: &ChunkIntegrity, body) -> Result<(), VerifyError>`
  — sabit-zaman karşılaştırma + `subtle::ConstantTimeEq`.
- `VerifyError::WrongTagLength` vs `TagMismatch` — farklı hata varyantları timing
  kanalı oluşturur mu?
- `PayloadAssembler::verify_chunk_tag` async pipeline — race condition yoktur mi?

### 2.5 Trust Store — Orta Öncelik

**Dosya:** `crates/hekadrop-core/src/settings.rs` (`TrustedDevice`, `is_trusted_by_hash`)
**Dosya:** `crates/hekadrop-core/src/identity.rs` (`DeviceIdentity`)

**Kapsam:**
- `DeviceIdentity` — uzun süreli keypair + cihaz adı (`identity.json`).
- `TrustedDevice` — `peer_hash: [u8; 6]` ile eşleştirme (PairedKeyEncryption).
- `is_trusted_by_hash(peer_hash: &[u8]) -> bool` — constant-time eq mi?
- `add_trusted_device` / `remove_trusted_device` — race condition?

**Audit odak noktaları:**
- 6-byte hash truncation yeterli mi veya collision riski var mı? (Issue #17)
- `TrustedDevice` serialize/deserialize — JSON injection?
- Identity file permissions (0600): platform-specific shim doğru mu?

### 2.6 Payload Assembly ve Path Traversal — Orta Öncelik

**Dosya:** `crates/hekadrop-core/src/payload.rs`
**Dosya:** `crates/hekadrop-core/src/folder/sanitize.rs`

**Kapsam:**
- `PayloadAssembler::ingest` — peer-controlled `payload_id`, `offset`, `total_size`,
  aritmetik overflow koruması.
- `sanitize_received_name(raw: &str) -> Option<String>` — path traversal,
  `..`, null byte, absolute path engelleme.
- File size guard (`file_size_guard.rs`) — 1 TiB per-file + global cap.
- Symlink rejection — `follow_symlinks: false` enforced mi?

**Audit odak noktaları:**
- Peer-controlled `FileMetadata.size` ile `total_size` güveni: checked arithmetic
  (`compute_recv_percent`).
- Path sanitize: Windows/macOS/Linux'ta `\`, `:`, NULL, `..` farklı davranışları.
- TOCTOU: dosya sistemi erişimi ile sanitize arasında race?
- Folder bundle (RFC-0005) extract: `HEKABUND` format atomic-reject — staging dir
  + Drop guard doğruluğu.

### 2.7 Rate Limiting ve Server Accept Loop — Düşük-Orta Öncelik

**Dosya:** `crates/hekadrop-core/src/server.rs`

**Kapsam:**
- `accept_loop` — 32 concurrent bağlantı semaphore (`CONCURRENT_LIMIT`).
- IP-bazlı rate limit: 10 istek / 60 saniye (`RATE_LIMIT_WINDOW`,
  `RATE_LIMIT_MAX`).
- Slow-loris guard: `HEADER_TIMEOUT = 10s` + `STEADY_READ_TIMEOUT = 60s`.

**Audit odak noktaları:**
- Rate limit bypass: IPv6 → v4 mapping, loopback exemption?
- `DashMap` ile `HashMap` race condition (thread-safety)?
- `frame::read_frame_timeout` deadlock potansiyeli?

---

## 3. Kapsam Dışı (Bu Audit İçin)

- **UI katmanı** (`hekadrop-app/src/ui/`, wry/tao/WebView2) — Web content
  sandbox'ı içinde; XSS UKEY2 güvenliğini etkilemez.
- **mDNS advertising** — Passive discovery; attacker zaten LAN'da demek.
- **Auto-update mekanizması** — Ayrı audit PR'ı (#TBD).
- **CLI stub** (`hekadrop-cli`) — Minimal, güvenlik yüzeyi yok.
- **Windows/Linux platform shims** — Native API binding'leri; kapsam ayrı.
- **i18n / l10n** — UI metin, güvenlik etkisi yok.

---

## 4. Bağımlılık Güvenlik Durumu

| Bileşen | Crate | Sürüm | Durum |
|---|---|---|---|
| ECDH | `p256` | 0.13.2 | RustCrypto; son auditli sürüm |
| AES-256-CBC | `aes` + `cbc` | 0.8.4 + 0.1.2 | RustCrypto; production-ready |
| HMAC-SHA256 | `hmac` | 0.12.2 | RustCrypto |
| SHA-2 | `sha2` | 0.10.9 | RustCrypto |
| HKDF | `hkdf` | 0.12.4 | RustCrypto |
| Sabit-zaman | `subtle` | 2.6.1 | Invariant: const-time eq |
| Protobuf | `prost` | 0.14.3 | 0-unsafe; generated code incelenmeli |
| Async runtime | `tokio` | 1.52 | Güvensiz blok yok (core crate'de) |

**Bilinen RUSTSEC girişleri (GTK3 zinciri — wry upstream blocker):**
- RUSTSEC-2024-0411 → 0419: gtk-rs GTK3 bindings EOL. Platform GTK4'e
  geçene kadar (wry 0.56+) bu advisory'ler açık kalır; core kripto kodunu
  etkilemez.

---

## 5. Fuzz Coverage

10 harness (`fuzz/fuzz_targets/`) — see `docs/security/fuzzing.md` for full
inventory. Her harness "crash-free" çalışmalı; crash = audit blocker.

Çalıştırma:
```bash
cargo +nightly fuzz build   # tüm harness'ler derlenebilmeli
cargo +nightly fuzz run fuzz_ukey2_client_init -- -max_total_time=3600
```

---

## 6. Audit Deliverables

Harici audit ekibinden beklentiler:

1. **Kripto implementation review:** §2.1–2.4 kapsamındaki kod satırları
   için satır bazlı analiz.
2. **Threat model doğrulama:** `docs/security/threat-model.md` STRIDE
   tablosunda eksik veya yanlış risk rating tespiti.
3. **Fuzzing gözden geçirme:** Mevcut harness'lerin kapsam boşluklarını
   belgele; önerileri `fuzz/fuzz_targets/` PR'ı ile gönder.
4. **Bağımlılık audit:** Kullanılan RustCrypto crate'lerinde bilinen
   zafiyetler veya potansiyel riskler.
5. **Rapor formatı:** Markdown veya PDF; CVSS skorları ile birlikte;
   `SECURITY-ADVISORIES.md` için satır önerileri.

---

## 7. İletişim

- **Güvenlik açığı bildirimi:** GitHub Security Advisories (private) veya
  `destek@sourvice.com` PGP şifreli.
- **Audit scope soruları:** GitHub Discussions veya aynı e-posta.
- **NLnet başvurusu koordinasyonu:** Bkz. ROADMAP.md §Q2.
