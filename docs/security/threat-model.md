# HekaDrop Threat Model

**Belge sürümü:** v0.1 (ilk taslak)
**Tarih:** 2026-04-24
**Kapsanan HekaDrop sürümü:** `v0.6.x` (commit öncesi `refactor/pr5-review-fixes` branch; karşılaştırma `main` @ `57e7cc9`)
**Hedef kitle:** harici kripto audit ekipleri (Trail of Bits / Cure53 / NLnet grant reviewer'ları), dahili güvenlik review'cuları, katkıcılar.
**Framework:** Microsoft STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) + explicit attacker models.

Bu belge **implementation değişikliği önermez**; mevcut durumu, mitigation'ları ve deferred risk'leri belgelendirir. Somut öneriler `docs/rfcs/` altındaki RFC'lerde.

---

## 1. System Description

HekaDrop, Google Quick Share (eski adıyla Nearby Share) protokolünün Rust ile yeniden yazılmış, LAN üzerinde çalışan cross-platform bir alıcı/gönderici istemcisidir. Amaç: stok Android cihazlarının share sheet'inden macOS/Linux/Windows makineye app kurmadan dosya/metin/URL göndermesi. Protokol Google'ca yayınlanmadığı için implementasyon NearDrop / rquickshare reverse-engineering çalışmalarına ve `securegcm`/`securemessage` proto dosyalarına dayanır. Desteklenen platformlar: macOS 10.15+, Linux glibc 2.31+/GTK3, Windows 10 1809+.

**Ağ akışı:**

1. **Discovery (mDNS):** `_FC9F5ED42C8A._tcp.local.` servis adı altında TXT kayıtlarıyla (cihaz adı, endpoint_id) yayın. `src/mdns.rs`, `src/discovery.rs`.
2. **TCP accept:** Sabit port `47893` (override: `HEKADROP_PORT`), 32 concurrent bağlantı semaphore, IP-bazlı rate limit (10/60 sn). `src/server.rs:11`, `src/server.rs:22`, `src/state.rs:89-127`.
3. **Handshake (UKEY2):** `ConnectionRequest` → `Ukey2ClientInit` → `Ukey2ServerInit` → `Ukey2ClientFinished` → ECDH (P-256) + HKDF-SHA256 ile anahtar türetme + 4 haneli PIN. `src/ukey2.rs:240-469`.
4. **Secure channel:** Tüm sonraki trafik AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) altında `DeviceToDeviceMessage` wrapper'ı ile; 16 MiB frame cap, 60 sn idle timeout. `src/secure.rs:42-154`, `src/frame.rs:7,18`.
5. **Payload reassembly:** `PayloadTransfer` frame'leri `payload_id` başına `FileSink` / `TextSink` kuyruklarına birleştirilir; `FileMetadata.size` clamp + 1 TiB per-file cap; ad sanitization + symlink reddi. `src/payload.rs:250-470`, `src/file_size_guard.rs:43`, `src/connection.rs:1006-1065`.

**Kod giriş noktaları (audit için):**

| Alan                     | Dosya                          | Bölüm                     |
|--------------------------|--------------------------------|---------------------------|
| TCP accept + rate limit  | `src/server.rs`                | `accept_loop`, L50-83     |
| Per-peer state machine   | `src/connection.rs`            | `handle`, L70-900         |
| UKEY2 handshake          | `src/ukey2.rs`                 | tüm modül                 |
| Secure framing           | `src/secure.rs`                | `SecureCtx::encrypt/decrypt` |
| Kripto primitif wrapper  | `src/crypto.rs`                | tüm modül                 |
| Payload reassembly       | `src/payload.rs`               | `PayloadAssembler`        |
| Ad sanitize              | `src/connection.rs`            | `sanitize_received_name` L1006 |
| URL şema allow-list      | `src/connection.rs`            | `is_safe_url_scheme` L1075 |
| Trust store              | `src/settings.rs`              | `TrustedDevice`, L220-505 |
| Cihaz uzun-süreli kimlik | `src/identity.rs`              | `DeviceIdentity`          |

---

## 2. Trust Boundaries

```
                 ┌────────────────────────────────────────────┐
                 │            End User (Alice)                │
                 │        - Ekran + klavye (PIN okur)         │
                 │        - Consent dialog'una OK/İptal        │
                 └──────────────┬─────────────────────────────┘
                                │ TB-1: User ↔ App
                                ▼
┌────────────────────────────────────────────────────────────────┐
│                   HekaDrop süreci (user-level)                 │
│                                                                │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐    │
│  │ mDNS ilanı   │   │ UKEY2 + AES  │   │  PayloadAssembler │    │
│  │ src/mdns.rs  │   │ src/ukey2.rs │   │  src/payload.rs   │    │
│  └──────┬───────┘   │ src/secure.rs│   └─────────┬────────┘    │
│         │           └──────┬───────┘             │             │
│         │                  │                     │             │
│         │                  │                     ▼             │
│         │                  │        ┌──────────────────────┐   │
│         │                  │        │ config_dir/          │   │
│         │                  │        │  identity.key (0600) │   │
│         │                  │        │  config.json         │   │
│         │                  │        │  (trusted_devices[])│   │
│         │                  │        └──────────┬───────────┘   │
└─────────┼──────────────────┼───────────────────┼───────────────┘
          │ TB-2: LAN        │ TB-2: LAN         │ TB-4: App ↔ OS
          ▼                  ▼                   ▼
   ┌──────────────────────────────┐   ┌────────────────────────┐
   │ Yerel ağ segmenti            │   │ Host OS                │
   │ (Wi-Fi, Ethernet)            │   │  - filesystem          │
   │  - Başka peer'lar            │   │  - logs_dir (rolling)  │
   │  - Rogue AP / MITM adayları  │   │  - Keychain/Secret svc │
   └──────────────┬───────────────┘   │    (ŞU AN KULLANILMIYOR)│
                  │                   └───────────┬────────────┘
                  │ TB-3: App ↔ Peer              │ TB-5: App ↔ FS (Downloads)
                  ▼                               ▼
         ┌──────────────────────┐       ┌────────────────────┐
         │ Remote Peer          │       │ ~/Downloads/       │
         │  (Android/Win/Linux) │       │  (user-writable)   │
         │  attacker-controlled │       │                    │
         │  olabilir            │       └────────────────────┘
         └──────────────────────┘
```

**Trust boundary özeti:**

| TB  | Sınır                    | Güven yönü / varsayım                                          |
|-----|--------------------------|-----------------------------------------------------------------|
| TB-1| User ↔ App               | User PIN'i doğru okur ve dialog'da bilinçli karar verir        |
| TB-2| App ↔ LAN                | LAN düşmandır; tüm trafik şifreli+authenticated olmalı         |
| TB-3| App ↔ Peer               | Peer **yarı-güvenilirdir** (kullanıcı onayı sonrası); protokole uysa da kötü amaçlı payload üretebilir |
| TB-4| App ↔ OS (keychain/net)  | OS güvenilir; aynı-kullanıcı başka süreçler güvenilir değil (RFC-tracked)|
| TB-5| App ↔ Filesystem         | Download dir kullanıcıya ait; sanitize + symlink guard gerekli  |

---

## 3. Assets

| ID  | Varlık                                            | Savunulan özellik(ler)        | Etki |
|-----|---------------------------------------------------|-------------------------------|------|
| A-1 | Transfer içeriği (dosya bayt'ları, metin, URL)    | Confidentiality, Integrity   | Yüksek |
| A-2 | Quick Share servisi (port 47893, mDNS ilanı)      | Availability                  | Orta |
| A-3 | Trusted peers listesi (`config.json`)             | Integrity, Confidentiality    | Yüksek |
| A-4 | Cihaz uzun-süreli anahtarı (`identity.key`, 32 B) | Confidentiality (kritik)      | Kritik |
| A-5 | UKEY2 oturum anahtarları (`encrypt/decrypt_key`)  | Confidentiality (ephemeral)   | Yüksek |
| A-6 | Host filesystem (Downloads dir dışı yazma hakkı)  | Integrity (no-escape)         | Kritik |
| A-7 | Log dosyaları (rolling 3 gün, user-readable)      | Confidentiality (PII)         | Düşük-Orta |
| A-8 | 4-haneli PIN (handshake OOB doğrulaması)          | Entropy (14-bit; brute'e maruz) | Orta |

**Açıklamalar:**

* **A-4 (identity.key):** `src/identity.rs:100-117` — 32 bayt random, POSIX `O_EXCL + mode(0o600)`, Windows'ta `icacls /inheritance:r + *S-1-3-4:(F)`. Peer'a gönderilmez; yalnız HKDF türevi `secret_id_hash` (6 bayt) paylaşılır (`src/identity.rs:127-137`).
* **A-5 (session keys):** `DerivedKeys` struct (`src/ukey2.rs:26-38`) ephemeral — oturumla birlikte düşer. `auth_key` sadece `session_fingerprint` (log relate) için saklanır (`src/crypto.rs:59-62`).
* **A-6 (filesystem):** Path traversal (`sanitize_received_name`, `src/connection.rs:1006-1065`) + symlink race (`src/payload.rs:341-360`) + reserved device names + NTFS ADS (`:`) engelleri.
* **A-8 (PIN):** Entropi 9973 mod (yaklaşık 13.28 bit). Yalnız kullanıcının **ekranda gördüğü** değer vs. karşı cihazda gösterilen değerin **görsel** karşılaştırması için; handshake'te cryptographic binding `auth_key` ile yapılır (`src/crypto.rs:38-48`).

---

## 4. Attacker Models

| ID  | Adversary                        | Kapasiteler                                                                 | Kısıtlamalar                                               |
|-----|----------------------------------|------------------------------------------------------------------------------|-------------------------------------------------------------|
| A1  | Passive LAN eavesdropper         | Tüm LAN trafiğini okur (tcpdump, switch span port, Wi-Fi açık SSID)          | Paket inject edemez; aktif MITM yapamaz                     |
| A2  | Active LAN attacker              | ARP poisoning, rogue mDNS responder, DNS spoofing, TCP paket inject          | Peer'ın private long-term key'ini elde edemez; PIN'i göremez|
| A3  | Malicious peer device            | Protokolün her aşamasında spec-ihlali veya crafted mesaj gönderir; PIN'i hedef kullanıcıdan alabilir (aynı odada) | Kullanıcı onayı olmadan trust store'a yazamaz              |
| A4  | Stale trusted device             | Daha önce trusted ilan edilmiş; artık fiziksel kontrolü saldırganda (çalıntı telefon, evden ayrılmış çalışan) | Identity key'i elde etmediyse `secret_id_hash` değişmez; TTL süresi içinde aktif olmalı |
| A5  | Host-level malware (user-level)  | Aynı kullanıcı olarak `~/Downloads`, `config_dir`, log dosyalarını okur/yazar; env var değiştirir | root/admin yok; OS kernel + syscall tablosuna dokunamaz    |
| A6  | Supply-chain attacker            | `cargo` registry üzerinden kötü amaçlı sürüm publish eder; build-time proc macro çalıştırır | HekaDrop CI `cargo deny` + `cargo audit` + lockfile kontrolü ile korunur |

**Ortak varsayımlar:** Saldırgan Kerckhoff ilkesine uygun olarak HekaDrop kaynak koduna, Quick Share spec'ine, reverse-engineered protobuf tanımlarına tam erişime sahip kabul edilir.

---

## 5. STRIDE Analysis (per component)

### 5.1 Discovery (mDNS)

| STRIDE | Somut saldırı                                            | Mevcut mitigation                                           | Eksik / deferred                                    |
|--------|----------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------|
| **S**  | A2: Rogue peer "Alice'in iPhone'u" adıyla ilan eder       | mDNS ad peer-controlled zaten; trust kararı ad'a değil `secret_id_hash`'e bağlıdır (`src/connection.rs:615`, Issue #17) | Discovery'de imza yok (Quick Share spec'i permit etmiyor) |
| **T**  | A2: mDNS TXT kayıtlarında `endpoint_id` tampered          | `endpoint_id` trust kararında kullanılmıyor; yalnız UI etiketi | — |
| **I**  | A1: HekaDrop kurulu cihazları tespit (reconnaissance)    | `advertise=false` "receive-only" modu (`src/settings.rs:241`)| mDNS listen hâlâ pasif bilgi sızdırır |
| **D**  | A2: mDNS daemon'a flood query (Pi-hole gibi memory bloat) | `mdns-sd` crate bounded kuyruk                              | mDNS özel stress test'imiz yok                      |
| **E**  | —                                                        | Discovery kod yolu doğrudan filesystem/process manipülasyonu yapmaz | — |

### 5.2 Handshake (UKEY2)

| STRIDE | Somut saldırı                                            | Mevcut mitigation                                           | Eksik / deferred                                    |
|--------|----------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------|
| **S**  | A2: MITM, her iki tarafa ayrı ephemeral key sunar (klasik DH-MITM) | UKEY2 cipher commitment (SHA-512 of `ClientFinished`) + 4-haneli PIN her iki tarafta auth_key'den türetilir → kullanıcı görsel karşılaştırmayla MITM'i tespit eder (`src/ukey2.rs:369-381`, `src/crypto.rs:38-48`) | PIN 14-bit; kullanıcı göz karşılaştırmayı atlarsa MITM riskine açık (A8, oto-kabul ile ağırlaşır) |
| **S**  | A3: Peer cipher downgrade (`P256_SHA512` yerine `Curve25519_SHA512`) | `validate_server_init` explicit reddeder (`src/ukey2.rs:222-230`, test 515-532) | — |
| **S**  | A3: UKEY2 version downgrade (`version=0`, `None`)         | `validate_server_init` — yalnız V1 (`src/ukey2.rs:226-228`)  | — |
| **T**  | A3: `Ukey2ClientInit` içinde 10 000+ `CipherCommitment` flood → CPU/RAM yeme | 8 commitment üst sınırı (`src/ukey2.rs:282-284`, `HekaError::CipherCommitmentFlood`) | — |
| **T**  | A3: `ClientFinished` içinde yanlış P-256 point (küçük alt grup) | `EncodedPoint::from_bytes` + `PublicKey::from_encoded_point` cofactor-valid point kontrolü (`p256` crate, `src/ukey2.rs:425-430`) | Ekstra cofactor-check review audit'te doğrulanmalı |
| **T**  | A3: `cipher_commitment` mismatch (farklı public key göndermek) | SHA-512 commitment doğrulaması (`src/ukey2.rs:373-381`) | — |
| **R**  | A3: Session sonrası peer inkâr eder                      | `session_fingerprint(auth_key)` log'a yazılır (`src/crypto.rs:59-62`) | Non-repudiation yok; ECDSA-imzalı transcript yok (v1.0 hedefi) |
| **I**  | A1: Handshake'ten PIN'i inference — PIN `auth_key`'in deterministic fonksiyonu; `auth_key` ECDH output'tan türetilir, ECDH her iki tarafın private key'ine bağlıdır → A1 göremez | ECDH + HKDF + OsRng | — |
| **I**  | Log'a PIN clear-text sızar mı?                             | `session_fingerprint` yazılır, PIN değil (`src/connection.rs:133-140`) | — |
| **D**  | A3: Slow-loris — ClientInit'in ilk baytından sonra sonsuz bekleme | `HANDSHAKE_READ_TIMEOUT = 30s` (`src/frame.rs:12`) + 32 connection semaphore + IP rate limit | 30 sn cömert; audit küçültmeyi değerlendirebilir |
| **D**  | A2: SYN flood                                             | OS TCP stack (SYN cookies)                                  | Kontrol sistem-düzeyinde; HekaDrop scope dışı      |
| **E**  | Handshake parse'ında buffer overflow → RCE                | Rust memory safety + `prost` decode; `unsafe` bloğu yok (grep: 0 hit `unsafe` ukey2.rs'de) | `prost` kendi içinde unsafe içerir — audit scope   |

### 5.3 Transfer (Secure channel + Payload)

| STRIDE | Somut saldırı                                            | Mevcut mitigation                                           | Eksik / deferred                                    |
|--------|----------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------|
| **S**  | A1/A2: Captured ciphertext'i farklı oturuma replay        | Session-specific `encrypt_key` (HKDF'de `clientInit\|\|serverInit` context) + sequence numarası | — |
| **T**  | A2: Ciphertext bit-flip (CBC malleability)                | HMAC-SHA256 tag, **header_and_body üzerine** hesaplanır (EtM — Encrypt-then-MAC). `src/secure.rs:78,113` (imza önce doğrulanır, sonra decrypt) | ✓ EtM doğru sıralı; audit bu konuyu özellikle gözden geçirsin |
| **T**  | A3: Aynı oturumda frame yeniden sıralama / replay         | `sequence_number` monotonik `+1` (`src/secure.rs:132-150`) + overflow guard (`checked_add`, L138-141) | — |
| **T**  | A3: HMAC tag truncation oracle (kısa tag gönder)           | `signature.len() != 32` → `HekaError::HmacTagLength` (`src/secure.rs:110-112`) | — |
| **T**  | A1/A2: Padding oracle (CBC PKCS#7 hata sızıntısı)         | Hata yolu tek generic `HekaError::HmacMismatch` / generic AES decrypt err; timing sızıntısı: `subtle::ConstantTimeEq` kullanılıyor (`src/crypto.rs:10,82`) | AES-CBC fundamentally padding-oracle'a maruz; EtM bunu maskeler ama BEAST/Lucky13 gibi subtle timing'e karşı yalnız crate-düzeyi garanti — audit gerekli |
| **R**  | A3: Transferi alıp sonra "hiç göndermedim" der             | Log'da `session_fingerprint` + `sha256(file)` (stats.json) var ama cryptographic proof yok | Non-repudiation v1.0 hedefi değil |
| **I**  | A1: CBC traffic analysis (uzunluk/zamanlama → dosya fingerprinting) | Padding PKCS#7 (max 16 B noise); dosya boyut meta-data `FileMetadata.size` içinde şifreli | Length-hiding padding yok — deferred |
| **I**  | A5: Host-level malware `config.json`'daki trusted peer listesini okur | `config_dir/` default ACL (POSIX 0700, NTFS user-only) | Keychain/Secret Service integration YOK — bilinen deferred risk |
| **I**  | A5: Log dosyasından dosya adları sızar                    | `log_redact::path_basename`, `sha_short`, `url_scheme_host` (`src/log_redact.rs:20-62`) | Basename hâlâ paylaşılırken ifşa olur; audit paylaşım işakış review'u |
| **D**  | A3: `FileMetadata.size = i64::MAX` → pre-allocate paniği  | `classify_file_size` clamp + reject (`src/file_size_guard.rs:43-51`), 1 TiB üst sınır | — |
| **D**  | A3: `total_size=10` ama sonsuz chunk gönder                | Cumulative overrun guard (`src/payload.rs:388-400`) + per-file cap | — |
| **D**  | A3: Frame flood (16 MiB frame × N)                        | Frame cap (`src/frame.rs:7`) + steady read timeout 60s (`src/frame.rs:18`) + 32 concurrent cap | Per-IP bandwidth cap yok |
| **D**  | A2: Ghost peer flood (her bağlantı UKEY2 handshake başlatıp bırakıyor) | IP rate limiter 10/60s (`src/state.rs:98-127`) + Issue #17 fix: trust muafiyet yalnız hash doğrulandıktan sonra geri uygulanır (`src/connection.rs:79-101`, commit `52e4ff1`) | Farklı IP'lerden koordineli flood hâlâ mümkün (IPv6 address pool) |
| **E**  | A3: Path traversal `name = "../../.bashrc"` → arbitrary write | `sanitize_received_name` basename-only + `.`/`..` reject + control char filter + Windows reserved + ADS `:` (`src/connection.rs:1006-1065`) | Unicode homoglyph edge case'leri fuzz-test'e açık |
| **E**  | A3: Symlink race (TOCTOU) — placeholder'ı symlink'e çevir | `std::fs::symlink_metadata` check (`src/payload.rs:341-360`) + `create_new(true)` atomic reserve (`src/connection.rs:937-948`) | Aynı inode'a hardlink saldırısı teorik; dosya sistemi capability-aware değil |
| **E**  | A3: URL payload `javascript:` / `file://` ile `open_url()` | `is_safe_url_scheme` allow-list yalnız `http(s)://` (`src/connection.rs:1075-1081`) | — |

### 5.4 Trust Store

| STRIDE | Somut saldırı                                            | Mevcut mitigation                                           | Eksik / deferred                                    |
|--------|----------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------|
| **S**  | A3: Saldırgan başka cihazın trusted adını spoof eder + rate-limit bypass | Issue #17 fix: gate'de muafiyet yok; trust kararı `secret_id_hash` (HKDF'den `identity.key`) ile verilir (`src/connection.rs:79-101,615`) | Legacy `(name,id)` kayıtları 3 sürümlük soft-sunset window; v0.8'de kaldırılmalı |
| **T**  | A5: Host malware `config.json`'a sahte trusted kayıt ekler | `atomic_write` + user-only ACL; `identity.key` harden (`src/settings.rs:731-780`, `src/identity.rs:159+`) | Plaintext JSON — Keychain integration deferred |
| **R**  | Trust'ı kim, ne zaman verdi?                              | `trusted_at_epoch` field                                    | User-viewable audit log UI yok (listeleme var; diff yok)|
| **I**  | A5: `trusted_devices[]` listesi okunur — sosyal grafik leak | POSIX 0600 config, aynı-kullanıcı malware'e açık            | OS keystore entegrasyonu YOK                         |
| **D**  | `trusted_devices` unbounded growth                        | Manuel temizleme UI                                          | `trust_ttl_secs` default 7 gün (`src/settings.rs:231`) — `0` sonsuz |
| **E**  | —                                                        | Trust store kendi başına komut çalıştırmaz                   | — |

### 5.5 UI (Consent dialog, notifications)

| STRIDE | Somut saldırı                                            | Mevcut mitigation                                           | Eksik / deferred                                    |
|--------|----------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------------------|
| **S**  | A3: Peer cihaz adını `"System Update"` yapar → kullanıcı kandırır | Ad peer-controlled; UX bildirim `device_name`'in salt metin olduğunu açıkça işaretler — `sanitize_field` kontrol karakterleri ayıklar (`src/ui.rs:47,66`) | Homoglyph attack mitigation yok |
| **T**  | A3: Newline injection ile dialog spoof (`"\n\nHacker: Accept?"`) | `sanitize_display_text` + `sanitize_field` + AppleScript escape (`src/ui.rs:73,111-114`) | — |
| **I**  | A3: Notification body'sinde PIN ifşa olur → yan ekrandaki kamera/izleyici görür | PIN UI'da **kullanıcıya** gösterilir (tasarım gereği); notification yalnız "eşleşme onayla" der, PIN'i dahil eder (user-device'ta) | Screen lock bypass OS-level konu |
| **D**  | macOS AppleScript deadlock / timeout                      | Process timeout + notify fallback                            | — |
| **E**  | AppleScript injection                                     | `escape_applescript` + control char strip (`src/ui.rs:111-114`) | — |

---

## 6. Cryptographic Review Scope

### 6.1 UKEY2 Handshake

* **Curve:** P-256 (`p256` crate, `elliptic-curve` 0.13.x). Nokta deserialize `EncodedPoint::from_bytes` → `PublicKey::from_encoded_point` (`src/ukey2.rs:427-430`, `src/ukey2.rs:141-144`). Küçük alt-grup ve geçersiz eğri saldırılarına karşı `p256` library-level cofactor validation'a güveniyoruz — **audit'in özel olarak doğrulaması istenir**.
* **Cipher commitment:** SHA-512 of serialized `Ukey2Message` (CLIENT_FINISH), `src/ukey2.rs:76-80`. Hash-then-MAC yerine hash-only; commitment schema UKEY2 spec'i ile uyumlu.
* **Downgrade koruması:** `validate_server_init` (`src/ukey2.rs:222-230`) — yalnız `P256_SHA512` + version `1`. Regression test coverage: `src/ukey2.rs:515-559`.
* **X.509-lite:** `GenericPublicKey` proto, Java `BigInteger.toByteArray()` signed-byte uyumlu enkod (MSB ≥ 0x80 ise 0x00 prefix) — `to_signed_bytes`, `src/ukey2.rs:199-208`. Android interop için zorunlu; audit algoritma uyumunu doğrulasın.

### 6.2 AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

**Composition:** Encrypt-then-MAC. Encrypt path:

```
plaintext → AES-256-CBC-PKCS7 → ciphertext
HMAC tag = HMAC-SHA256(send_hmac_key, HeaderAndBody_bytes)
SecureMessage{ header_and_body, signature=tag }
```

(`src/secure.rs:58-84`). Decrypt path **önce** HMAC verify, sonra AES decrypt (`src/secure.rs:113-129`) — padding oracle'ı mask eden klasik EtM.

* **Padding:** PKCS#7 via `cbc::Decryptor<Aes256>::decrypt_padded_vec_mut::<Pkcs7>` (`src/crypto.rs:89-95`). HMAC fail durumunda padding hiç kontrol edilmez → Lucky13 tarzı yan kanal minimize.
* **IV:** Her mesaj için `rand::thread_rng().fill_bytes(&mut iv[16])` (`src/secure.rs:57-58`). `thread_rng` ChaCha12-based CSPRNG (`rand` crate `StdRng` default); `OsRng` ile reseeded. Audit: IV nonce-collision riskini `thread_rng` kalitesinden yola çıkarak değerlendirmeli.
* **Sequence number:** `i32`, `checked_add` ile overflow guard (`src/secure.rs:44-50, 138-141`).
* **Constant-time:** `subtle::ConstantTimeEq` HMAC verify içinde (`src/crypto.rs:10, 82`) + length guard erken bail (`src/crypto.rs:73-83`, `src/secure.rs:110-112`).

### 6.3 HKDF-SHA256 Key Separation

Tüm anahtar türetme `crypto::hkdf_sha256(ikm, salt, info, len)` (`src/crypto.rs:16-22`) üzerinden:

| Seviye | IKM                  | Salt                               | Info                   | Output                   |
|--------|----------------------|------------------------------------|-----------------------|--------------------------|
| 1      | `SHA-256(ECDH(X,Y))` | —                                  | `"UKEY2 v1 auth"`     | `auth_key` (32 B)        |
| 1      | `SHA-256(ECDH(X,Y))` | —                                  | `"UKEY2 v1 next"`     | `next_secret` (32 B)     |
| 2      | `next_secret`        | `D2D_SALT` (32 B sabit)            | `"client"` / `"server"` | `d2d_*_key` (32 B)     |
| 3      | `d2d_*_key`          | `SHA-256("SecureMessage")`         | `"ENC:2"` / `"SIG:1"` | AES + HMAC anahtarları    |

**`D2D_SALT`** Quick Share spec sabiti, `src/crypto.rs:103-106`:
```
82 AA 55 A0 D3 97 F8 83 46 CA 1C EE 8D 39 09 B9
5F 13 FA 7D EB 1D 4A B3 83 76 B8 25 6D A8 55 10
```
Audit: RFC 5869 domain separation yeterli mi, yoksa info string'lerde version/role bitleri gerekli mi?

### 6.4 Random Sources

| Kullanım                   | RNG                   | Dosya:satır                              |
|----------------------------|-----------------------|------------------------------------------|
| P-256 secret_key           | `rand::rngs::OsRng`   | `src/ukey2.rs:49, 312`                   |
| UKEY2 `random` 32 B        | `OsRng`               | `src/ukey2.rs:84, 333`                   |
| AES-CBC IV (hot path)      | `rand::thread_rng()`  | `src/secure.rs:58`                       |
| `identity.key` 32 B init   | `rand::thread_rng()`  | `src/identity.rs:101`                    |
| `payload_id`               | `thread_rng`          | `src/connection.rs:1175`, `src/sender.rs:105,403` |
| `endpoint_id`              | `thread_rng`          | `src/config.rs:20, 50`                   |

`thread_rng` — `rand` 0.8+ default `ChaCha12Rng`, per-thread, `OsRng` ile periyodik reseed. **Audit sorusu:** IV ve identity key için `thread_rng` vs. `OsRng` tercihi; `thread_rng` fork-safety ve uzun-yaşayan süreçte state forwardness garantileri yeterli mi?

### 6.5 Constant-time Comparisons

* HMAC: `subtle::ConstantTimeEq` (`src/crypto.rs:82`).
* PIN karşılaştırması: **kullanıcı yapıyor (görsel)** — uygulama dahilinde PIN equal-check yok.
* `secret_id_hash` eşleştirme: `src/settings.rs:307` `trusted_devices.iter().any(|d| …)` — naive `==`. **Audit:** trusted list lookup timing oracle riski (A5: yerel malware hash tahmini için timing ölçebilir mi?). Hash'in kendisi zaten peer tarafından bilinmiyor (`identity.key`'den türev), dolayısıyla exploitability düşük.

### 6.6 Nonce/IV Reuse Riski

* CBC IV 16 B random her mesajda yeniden üretiliyor. Birthday-bound: 2^64 mesaj sonrası collision beklenir; `i32` sequence counter zaten 2^31'de bail eder → pratikte ulaşılmaz.
* Oturumlar arası key farklı (HKDF context = full `clientInit||serverInit`); IV collision cross-session bile plaintext confidentiality'yi bozmaz.

### 6.7 PIN Entropisi ve Akışı

`pin_code_from_auth_key` (`src/crypto.rs:38-48`) NearDrop referans algoritması: `i8`-signed byte loop, `MOD=9973`, `mult*=31`. Deterministic, birebir Java interop. KAT test mevcut (`src/crypto.rs:140-197`). PIN uzunluğu 4 decimal hane → entropi ≈ log2(10000) = 13.29 bit. **Saldırı modelinde PIN cryptographic binding DEĞİL, sadece OOB görsel karşılaştırma**; handshake MITM güvencesi `auth_key` üzerinden geliyor. User attention failure = PIN'in tek savunması.

---

## 7. Non-Cryptographic Attack Surface

### 7.1 Path Traversal

Tam denetim yukarıda (§5.3 E-row). Doğrulama listesi:

1. Separator strip: `rsplit('/')` + `rsplit('\\')` (`src/connection.rs:1008-1009`).
2. `.`/`..` reject (L1012-1015).
3. Control + Windows-forbidden char filter (`< > : " / \ | ? *`) (L1017-1025).
4. Trailing dot/space trim (L1030-1034).
5. Reserved Windows device names check on **first-dot stem** — `CON.tar.gz` kapsanır (L1040-1053).
6. 200-byte UTF-8 aware truncate (L1056-1064).
7. Fallback `"dosya"`.

Test coverage: `src/connection.rs:1455+` (`sanitize_*` test bloğu). Fuzz-coverage fuzz/ altında mevcut (ayrı inceleme).

### 7.2 Rate Limiting Bypass (Issue #17 / PR #81)

Önceki davranış: gate öncesi `is_trusted_legacy(peer_name, peer_id)` muafiyet; peer-controlled string spoof → 10/60s bypass → 32-permit `Semaphore` doldur → meşru peer DoS. Fix (commit `52e4ff1`, PR #81):

* Rate limit HERKES'e uygulanır (`src/connection.rs:95-101`).
* `RateLimiter::forget_most_recent(ip)` (`src/state.rs:132-137`): PairedKey branch'inde `peer_secret_id_hash` doğrulandığında geriye-dönük muafiyet (`src/connection.rs:515-524`).
* Legacy `(name, id)` 3-version soft-sunset TTL.

### 7.3 Symlink Race (TOCTOU)

`unique_downloads_path` (`src/connection.rs:922-981`) `OpenOptions::create_new(true)` ile atomic reserve — `O_EXCL` (POSIX) / `CREATE_NEW` (Windows). 32 concurrent alıcı race'e karşı ispatlanmış.

`ingest_file` — `symlink_metadata` (`src/payload.rs:349-360`) link resolve etmeden tip kontrol; symlink tespit → iptal. Test: `src/payload.rs:690-713`.

**Kalan risk:** hardlink saldırısı (same-inode alt-dizinde placeholder olarak yaratıldıktan sonra A5 hardlink ekler) — `create_new` hardlink'e karşı koruma vermez; ama Downloads dir tipik olarak user-only ve hardlink için kaynak inode'a yazma izni zaten gerekir.

### 7.4 Resource Exhaustion

| Vektör                               | Limit                                                      | Dosya                          |
|--------------------------------------|------------------------------------------------------------|--------------------------------|
| TCP frame size                       | 16 MiB (`MAX_FRAME_SIZE`)                                  | `src/frame.rs:7`               |
| Concurrent connections               | 32 semaphore                                               | `src/server.rs:22`             |
| Per-IP conn rate                     | 10 / 60 sn                                                 | `src/state.rs:98-99`           |
| UKEY2 cipher commitments             | 8                                                          | `src/ukey2.rs:282`             |
| Per-file size                        | 1 TiB (`MAX_FILE_BYTES`)                                   | `src/file_size_guard.rs:25`    |
| Handshake idle                       | 30 sn timeout                                              | `src/frame.rs:12`              |
| Steady-state idle                    | 60 sn timeout                                              | `src/frame.rs:18`              |
| FileSink unique name attempts        | 10 000                                                     | `src/connection.rs:977`        |

### 7.5 Log Disclosure

`src/log_redact.rs` — `path_basename`, `sha_short` (ilk 16 hex), `url_scheme_host` (userinfo + path + query strip). Bilinçli olarak redact EDİLMEYEN'ler (modül doc 9-13): IP adresleri, `endpoint_id`, UI bildirimleri. Log paylaşım senaryosu için yeterli; PII-audit için eksiklikler audit'te not edilebilir (örn. `device_name` field'ı redact edilmiyor).

---

## 8. Known Deferred Risks (Accepted for v0.x)

Aşağıdaki riskler **bilinçli** olarak v0.x serisi için deferred; v1.0.0 release kriterlerinde (`docs/ROADMAP.md` §0.2) bir kısmı DoD'a dahil.

| ID  | Risk                                                     | Neden accept                                             | Planlanan giderme        |
|-----|----------------------------------------------------------|----------------------------------------------------------|--------------------------|
| D-1 | Trust store **plaintext JSON**, Keychain/Secret Service yok | GTK3/wry ekosisteminde cross-platform keychain crate'i olgun değil; kullanıcı config'i editlemek istiyor | v0.9 (pre-v1.0 hardening) |
| D-2 | Per-chunk authenticated encryption yok — bütün dosya EtM sargısı altında tek HMAC | Quick Share spec uyumluluğu bozmamak; Android peer'larla interop | v0.8 |
| D-3 | Resume protokolü yok                                     | Quick Share `PayloadTransfer.offset` henüz read-only     | v0.8 |
| D-4 | GTK3 EOL (RUSTSEC-2024-041*)                             | `wry` cross-platform webview; gtk4-rs migration upstream'de | Upstream wry 0.50+ sonrası |
| D-5 | Non-repudiation (ECDSA signed transcript) yok            | v1.0 sonrası pairing protokolü kapsamında                | v1.0+ |
| D-6 | Length-hiding padding yok (CBC traffic analysis)         | Quick Share spec'te yok; Android peer kabul etmez        | v1.0+ (Magic Wormhole transit modunda opsiyonel) |
| D-7 | Legacy `(name, id)` trust match (3-version window)       | Kullanıcı upgrade path'i                                 | v0.8'de kaldırılacak |
| D-8 | `auto_accept=true` + trust store bir arada kullanıcı-facing risk amplifier | Opt-in, varsayılan false                                 | v0.8 UI uyarıları |

`deny.toml` üzerinde accept edilen RUSTSEC advisory'leri (her biri için gerekçe `deny.toml:7-38`):

| Advisory          | Neden                                    |
|-------------------|-------------------------------------------|
| RUSTSEC-2024-0411..0420 | gtk3-rs ailesi "archived"; gtk4-rs migration wry 0.50+'te. |
| RUSTSEC-2024-0370 | `proc-macro-error` build-time only, runtime yüzeyi yok. |
| RUSTSEC-2024-0429 | `glib::VariantStrIter` unsound; biz ve wry bu iteratörü kullanmıyoruz (grep doğrulandı). |

---

## 9. External Audit Scope (Trail of Bits / Cure53 / NLnet Reviewers)

Aşağıdaki alanları external auditor'ın **öncelikli** olarak ele alması istenir:

1. **UKEY2 implementasyonu vs. reference:**
   - `src/ukey2.rs` tüm modül.
   - Google'ın referans Java `Ukey2Handshake` sınıfı ile protokol akışı eşleşmesi.
   - Commitment sırası, Sha512 kapsamı, `client_init||server_init` transcript binding doğruluğu.
   - P-256 cofactor validation ve küçük alt-grup saldırı resistance (p256 crate 0.13).
2. **AES-CBC + HMAC composition:**
   - `src/secure.rs:42-154` encrypt/decrypt path'i.
   - EtM sıralaması (MAC önce, decrypt sonra) — Moxie Marlinspike'in "cryptographic doom principle" compliance.
   - CBC padding oracle / Lucky13-type timing sızıntısı `subtle` kullanımı ötesinde.
3. **HKDF usage ve KDF-key separation:**
   - `src/crypto.rs:16-22` + §6.3 tablosu.
   - Domain separation (info string'leri) sufficient mi?
   - `D2D_SALT` spec'e birebir uyum + test vector KAT.
4. **Random source quality:**
   - `thread_rng` vs. `OsRng` seçimi her call-site için (§6.4 tablo).
   - IV için `thread_rng` fork-safety ve uzun-process reseed davranışı.
   - `identity.key` init'i `thread_rng` yerine `OsRng` olmalı mı?
5. **Trust store ve PIN entropisi:**
   - 4-haneli PIN'in "OOB attention-based" güvencesinin threat model yeterliliği.
   - `secret_id_hash` 6 bayt'ın 2^48 collision resistance'ı kullanım bağlamında yeterli mi (saldırgan identity.key bilmeden hash'i tahmin edemiyor; ama hash truncation etkileri)?
6. **Fuzzing harness coverage:**
   - Mevcut fuzz target'ları (`fuzz/` altında) — frame parser, sanitize_received_name, UKEY2 message parser.
   - Gerekli ama henüz yok olanlar: SecureCtx::decrypt (ciphertext+MAC mutation), classify_file_size (i64 edge), PayloadAssembler state machine.
7. **Protokol state machine confusion:**
   - ConnectionRequest → ClientInit → ServerInit → ClientFinished → ConnectionResponse → SecureCtx sırası dışında gelen frame'lerde hata davranışı.
   - Peer `Alert` / beklenmedik message_type ile state fast-forward.
8. **Supply chain:**
   - `Cargo.lock` + `cargo deny` + `cargo audit` CI kapsamı.
   - `build.rs` içeriği (proto generation — `protoc-prebuilt` güvenilir mi?).

---

## 10. Bibliography

**Standards & specs:**
* RFC 5869 — HKDF (Krawczyk, Eronen, 2010). <https://datatracker.ietf.org/doc/html/rfc5869>
* RFC 2104 — HMAC (Krawczyk et al., 1997). <https://datatracker.ietf.org/doc/html/rfc2104>
* RFC 6234 — SHA family. <https://datatracker.ietf.org/doc/html/rfc6234>
* FIPS 197 — AES. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf>
* NIST SP 800-38A — Block cipher modes (CBC). <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf>
* NIST SP 800-56A Rev. 3 — ECDH key establishment.
* SEC 1 v2.0 — EC encoding (P-256). <https://www.secg.org/sec1-v2.pdf>
* Google UKEY2 — <https://github.com/google/ukey2>
* Google securemessage / securegcm — <https://github.com/google/securemessage>, <https://github.com/google/securegcm>

**Reverse-engineering references:**
* grishka/NearDrop — <https://github.com/grishka/NearDrop>
* Martichou/rquickshare — <https://github.com/Martichou/rquickshare>

**Security literature:**
* Shostack, A. — *Threat Modeling: Designing for Security*, Wiley 2014 (STRIDE).
* Marlinspike, M. — "The Cryptographic Doom Principle", 2011. <https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html>
* AlFardan & Paterson — "Lucky Thirteen", IEEE S&P 2013.

**HekaDrop internal:**
* `SECURITY.md` (disclosure policy), `docs/design/017-*.md` (Issue #17 RFC), `docs/ROADMAP.md` §0.2/§1, PR #81 / commit `52e4ff1`.

---

**Revizyon takibi:** Bu belge external auditor feedback'i sonrası v0.2'ye revize edilir. Her yeni protocol path (LocalSend v2, Magic Wormhole transit) eklendiğinde ilgili STRIDE tabloları genişletilir.
