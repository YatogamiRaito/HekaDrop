# RFC 0004 — Transfer Resume

- **Başlatan:** @architect (destek@sourvice.com)
- **Durum:** Draft
- **Oluşturulma tarihi:** 2026-04-24
- **Hedef sürüm:** v0.8.0 ("Protokol Sağlamlaştırma", 2026-07-31)
- **İlgili issue:** ROADMAP.md v0.8.0 §"Transfer resume" (satır 122-124)
- **İlgili RFC'ler:** `0003-chunk-hmac.md` (capabilities frame + partial chunk integrity — paralel yazılıyor), `0005-folder-payload.md` (klasör payload'ları için resume — paralel)
- **Wire-level spec:** `docs/protocol/resume.md`

---

## 1. Özet

Bu RFC HekaDrop v0.8.0 için **transfer resume** mekanizmasını tanımlar. Bugün bir
10 GiB ISO transferi 50. chunk'ta kopan Wi-Fi yüzünden kesildiğinde, kullanıcı
tekrar bağlandığında byte 0'dan başlamak zorunda kalıyor. Önerilen tasarım:
yeni bir `ResumeHint` protokol frame'i ile **receiver**, elinde tuttuğu yarım
dosyayı (`~/.hekadrop/partial/<session_id>_<payload_id>.part`) sender'a
"`offset`'e kadar geldim, SHA-256 şöyle" diye bildirir; sender yerel dosyayı
aynı offset'e kadar hash'leyip doğrularsa `send_file_chunks` döngüsünü o
offset'ten başlatır. Frame capabilities negotiation ile gate'lenir (bkz. RFC
0003); resume-capable olmayan peer'larla davranış bugünkü tam-restart akışıdır.
Partial dosyalar 7 gün TTL + 5 GiB disk bütçesi LRU eviction ile yönetilir,
dizin izinleri `0700 / 0600`, session kimliği UKEY2 auth-key fingerprint'in
düşük 8 byte'ından türetilir — böylece farklı handshake = farklı session =
resume yok.

## 2. Motivasyon

v0.7'de `PayloadAssembler` (`src/payload.rs:250-470`) her chunk'ı
`~/Downloads/` altında `<name>.part` olarak yazıyor; dosya tamamlanana kadar
`.part` uzantısıyla kalıyor ve ancak `last_chunk=true` gelince final isme
rename ediliyor. Peer tamamlamadan disconnect ederse
`remove_partial_file` (`src/payload.rs:474`) partial'ı siliyor — yani
**mevcut kod resume'u aktif olarak öldürüyor**. Bu davranış GC-per-connection
için doğru (kısa ömürlü memory'yi tutmayalım) ama kullanıcı deneyimi için kötü:

1. **10 GiB ISO, Wi-Fi cut @ %92** → 20+ dakika iş, baştan başla. Otel/cafe
   Wi-Fi'lerinde ve kalabalık 2.4 GHz spektrumunda günlük vaka.
2. **Battery death / sleep** → laptop sender ekranı kapandığında
   `tokio::select!` blokesi sonlanır, TCP RST; telefon alıcı `.part` dosyasını
   cleanup eder, kullanıcı uyandığında "yarım iş yok" sürprizi.
3. **Network switch mid-transfer** → kullanıcı Wi-Fi'dan Ethernet'e atladı;
   routing tablosu değişti, socket koptu. Bugün resume yok, dolayısıyla bu
   kullanıcıya "büyük dosya paylaşmak için önce kabloyu tak" önermek zorundayız.
4. **Mobil hotspot zaman sınırı** → Android tethering 30 dakikada battery-save
   kesiyor; 4 GiB proje tarball'ı asla tamamlanmıyor.

Rakip LAN paylaşım araçları (LocalSend, Syncthing) chunk seviyesinde resume
destekliyor; HekaDrop'un Quick Share protokolüne bağlı kalmak için ekstra iş
yapması gerekiyor (Quick Share upstream'de ResumeHint yok — aşağıda
geriye uyumluluk bölümünde ele alınıyor).

## 3. Ayrıntılı tasarım

### 3.1 Partial dosya yönetimi (receiver-side)

**Dizin yapısı:**

```
~/.hekadrop/
  partial/                      (mode 0700, yalnız owner)
    <session_id>_<payload_id>.part   (mode 0600)
    <session_id>_<payload_id>.meta   (mode 0600, JSON)
```

`<session_id>` 16 karakterlik lowercase hex (8 byte, bkz. §3.4),
`<payload_id>` Quick Share Introduction frame'inden gelen `i64`'ün decimal
gösterimi. Böylece isim `a3f1b82e6cd07419_5138472819.part` gibi olur.

`.meta` dosyası resume bilgisinin kalıcı halidir:

```json
{
  "version": 1,
  "session_id": "a3f1b82e6cd07419",
  "payload_id": 5138472819,
  "file_name": "ubuntu-24.04.iso",
  "total_size": 10737418240,
  "received_bytes": 9876543210,
  "chunk_hmac_chain": "base64(last-verified-chunk-HMAC)",
  "peer_endpoint_id": "ANDROID_PIXEL_8",
  "created_at": "2026-07-15T14:32:11Z",
  "updated_at": "2026-07-15T14:51:03Z"
}
```

**Neden ayrı meta dosyası?** `.part` sadece dosya byte'larını taşıyor
(`std::fs::File::set_len` ile `total_size`'a sparse-pre-allocate edilmiyor —
platform cross-compat için naive append). Resume için "hangi peer, hangi
session, hangi chunk'ta kaldık" bilgisi gerekli; bunu `.part` header'ına
koymak protocol byte'larını kirletirdi. Ayrı meta JSON okuma kolaylığı +
human-debug için.

**Finalize:** Son chunk geldiğinde (`last_chunk=true`) `PayloadAssembler`
dosyayı `~/Downloads/<name>` altına rename eder ve **hem `.part` hem `.meta`**
dosyalarını siler (`src/payload.rs` içinde mevcut `remove_partial_file`
genişletilir; 0.8'de `remove_partial_resource(session_id, payload_id)`
olarak refactor).

**Çekilen rename:** Rename best-effort; başarısız olursa (cross-device,
permission) final dizin üzerinde `.tmp` kopya + atomic rename fallback
uygulanır. Mevcut kod zaten böyle yapıyor (bkz. `src/payload.rs` ingest_file);
0.8'de sadece "rename sonrası `.meta` sil" adımı eklenir.

### 3.2 `ResumeHint` frame

**Yerleşim:** Capabilities negotiation'ı (RFC 0003) müteakip,
**Introduction frame**'inden sonra, payload'ın ilk `PayloadTransfer` chunk'ı
gelmeden önce. Sender Introduction gönderdikten sonra receiver iki olası
cevaptan biriyle devam eder:

- **Tazecik dosya** (partial yok veya süresi dolmuş) → normal `ConnectionResponse`
  akışı, sender chunk'ları byte 0'dan yollar.
- **Yarım dosya mevcut** → `ResumeHint` frame gönderir.

Protobuf tanımı (proto ağacına `proto/v2/resume.proto` olarak eklenir):

```protobuf
syntax = "proto3";
package hekadrop.protocol.resume.v1;

message ResumeHint {
  int64  session_id         = 1;   // UKEY2 auth_key low-8 bytes (bkz. §3.4)
  int64  payload_id         = 2;   // Introduction frame'deki file id
  int64  offset             = 3;   // Receiver'ın diske sağlam yazdığı byte sayısı
  bytes  partial_hash       = 4;   // SHA-256(file[0..offset]) (32 byte)
  int32  capabilities_version = 5; // RFC-0003 capabilities frame versiyonu
  bytes  last_chunk_tag     = 6;   // Opsiyonel: son doğrulanmış chunk-HMAC tag'i
                                    //   (RFC-0003 aktifse; yoksa boş)
}
```

Frame `V1Frame` içine yeni bir `FrameType::ResumeHint = 7` olarak eklenir
(mevcut 1-6 değerleri `HandshakeBegin`, `ConnectionRequest`, `Introduction`,
`PayloadTransfer`, `KeepAlive`, `Disconnection`; `7` serbest).

### 3.3 Partial-hash doğrulama

Receiver `.part` dosyasının `[0..offset]` aralığının SHA-256'sını hesaplar ve
`partial_hash` alanına yazar. Sender `ResumeHint` alınca:

1. `payload_id` Introduction'da zaten ilan edilmişti; local dosyayı aç.
2. Local dosyanın `[0..offset]` aralığını streaming SHA-256 ile hash'le
   (chunk başına 1 MiB okuma, `sha2::Sha256::update`).
3. Hash `ResumeHint.partial_hash` ile `constant-time eq` karşılaştırması
   (`subtle::ConstantTimeEq` zaten dependency).
4. **Eşit** → sender `send_file_chunks` döngüsünü `offset`'ten başlatır; ilk
   frame'de `PayloadChunk.offset = offset`.
5. **Eşit değil** → sender `ResumeReject { reason: HASH_MISMATCH }` frame'i
   yollar; receiver `.part` + `.meta` siler ve normal akışa düşer (byte 0'dan).

**Neden full-hash, incremental değil?** 10 GiB SHA-256 modern x86_64'te
~30 saniye (SHA-NI olmadan 200 MB/s). 20 dakika baştan-yükleme'den çok daha
kısa. İyileştirme RFC-0003 ile birlikte geldiğinde: her chunk'ın HMAC tag'i
`.part`'a yanına yazılır (ayrı `.hmacs` side-file veya `.meta` içinde base64
dizisi), sender sadece `last_chunk_tag`'i doğrular — O(1) karşılaştırma,
bandwidth-sabit. RFC-0003 ve 0004 için **ortak primitif**: chunk-HMAC zaten
hesaplanıyor; burada sadece ek olarak kalıcı tutuluyor.

### 3.4 Session identity

`session_id` UKEY2 handshake sonrası türetilen `auth_key`'in
**SHA-256(auth_key) fingerprint'inin düşük 8 byte'ı** olarak tanımlanır.
Helper `crypto::session_fingerprint` (bkz. `src/ukey2.rs:134-139`) zaten
mevcut; 16 hex karakter olarak log'da görülüyor. Bu RFC ilgili helper'ı
`pub(crate) fn session_id_i64(auth_key: &[u8]) -> i64` şeklinde
export eder:

```rust
pub(crate) fn session_id_i64(auth_key: &[u8]) -> i64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(auth_key);
    i64::from_be_bytes(digest[0..8].try_into().expect("SHA-256 output ≥ 8 byte"))
}
```

**Özellik:** Deterministic per-handshake (aynı ECDH shared secret + aynı nonce
→ aynı `session_id`). Fakat Quick Share UKEY2 handshake her bağlantıda
yeni ephemeral P-256 key çifti üretir → pratikte **her bağlantı yeni session**.
Yani resume sadece aynı peer-pair'inin bir önceki transfer'inden kalmış
`.meta` dosyası ile eşleşir ve **sadece** aynı peer (aynı long-term identity)
başarılı bir yeni UKEY2 + PIN doğrulamasıyla yeni bir session kurduğunda
çalışır. Rastgele saldırganın partial enumerate etmesi mümkün değil (§7).

**Not:** `session_id`'in kendisi UKEY2 sonrası bilindiği için sender da
aynı hesabı yapar; frame üzerinde doğrulama olarak kullanırız (receiver
gönderdiği `session_id` ≠ sender'ın hesapladığı `session_id` → frame drop).
Böylece replay/fake-resume saldırıları frame validation seviyesinde düşer.

### 3.5 Trust boundary

Resume işlemi **her yeni successful handshake + Introduction** akışı içinde
gerçekleşir. PIN doğrulaması her seferinde yapıldığı için ayrıca "trusted
device" (config.json'daki trust list) olma koşulu aranmaz; yani yeni bir peer
bile aynı `session_id`'ı üretebilir eğer önceki handshake aynı auth_key'e
çözülürse (ki UKEY2 bunu engelliyor). Tek ek: config'te
`resume_require_trusted: bool` (default `false`) flag'i bulunur — paranoya
kullanıcıları resume'u sadece daha önce trust edilmiş cihazlarla yapabilmek
için aktifleştirebilir.

### 3.6 Partial cleanup

İki tetikleyici + iki limit:

| Parametre | Default | Override | Açıklama |
|-----------|---------|----------|----------|
| TTL | 7 gün | `config.resume.ttl_days` | `.meta.updated_at` bu süreden eskiyse sil |
| Disk bütçesi | 5 GiB | `config.resume.budget_bytes` | `partial/` toplamı aşarsa LRU (oldest `updated_at` önce) |
| Tetikleyici | Uygulama açılışı | — | `spawn` anında `tokio::spawn(cleanup_sweep())` |
| Tetikleyici | Günlük | OS-scheduler | Linux `systemd --user timer`, macOS `launchd` plist, Windows Scheduled Task |

**LRU seçimi:** `updated_at` artan sırada sırala, budget aşılana kadar sil.
Aktif transfer sırasında silinmesin diye `PayloadAssembler` çalışan bir
session için `<session_id>_<payload_id>.*` dosyalarını **in-use lock**
olarak işaretler (memory'de HashSet; cleanup bu seti skip eder).

**Startup cleanup yeterli mi?** HekaDrop tray app — kullanıcı günlerce kapatmaz.
Bu yüzden OS scheduler gerekli. systemd template `dist/linux/hekadrop-cleanup.timer`,
launchd template `dist/macos/tr.sourvice.hekadrop.cleanup.plist`, Windows
Scheduled Task XML'i `dist/windows/hekadrop-cleanup.xml` olarak birlikte
gönderilir.

### 3.7 Sender tarafındaki döngü değişikliği

`send_file_chunks` (`src/sender.rs:767`) bugün `offset: i64 = 0` ile başlıyor.
Resume aktifse `start_offset` parametresi alacak:

```rust
async fn send_file_chunks(
    socket: &mut TcpStream,
    ctx: &mut SecureCtx,
    payload_id: i64,
    path: &Path,
    file_size: i64,
    peer_label: &str,
    file_name: &str,
    bytes_sent_before: i64,
    total_bytes: i64,
    start_offset: i64,         // <-- YENİ (default 0, resume ile >0)
    cancel: &CancellationToken,
) -> Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    if start_offset > 0 {
        file.seek(SeekFrom::Start(start_offset as u64)).await?;
    }
    let mut offset: i64 = start_offset;
    // ... kalan döngü aynen devam
}
```

Hash hesaplama SHA-256 final digest için "full file" istiyor; resume'da
`hasher` state'i kayboluyor. Çözüm: **dosyanın tamamı üzerinden bağımsız
SHA-256 sender tarafında** (zaten log'a bastığımız final hash) — resume
doğrulama hash'i ile karıştırılmamalı. Burada iki seçenek:

- (a) Resume'da final SHA-256'yı atla (log'a "resumed, SHA unknown" yaz).
- (b) `start_offset = 0`'dan file'ı paralel hash'le (background task), transfer
  bittiğinde join et.

**Karar: (a)**. Final SHA-256 zaten chunk-HMAC (RFC-0003) tarafından subsumed
edilir; v0.8'de "file-level SHA" zaten görsel/debug seviyesinde değil, chunk
integrity primer olacak.

## 4. Capabilities negotiation (RFC-0003 ile koordinasyon)

RFC-0003 capabilities frame'i tanımlıyorsa (henüz draft — **bkz 0003 açık
sorular**), resume şu bit'i talep eder:

```
capability bit: RESUME_V1 = 0x0002   (RFC-0003: CHUNK_HMAC_V1 = 0x0001)
capabilities_version (u32): monoton artan; v1 = 1
```

**Önerilen capabilities frame iskeleti** (RFC-0003'e giriş olarak):

```protobuf
message Capabilities {
  uint32 version  = 1;  // monoton artar
  uint64 features = 2;  // bitfield: RESUME_V1 | CHUNK_HMAC_V1 | ...
}
```

RFC-0003 capabilities tasarımını üstlenmezse, 0004 kendi `resume_capabilities`
frame'ini minimal tutar:

```protobuf
message ResumeCapabilities { uint32 version = 1; bool supported = 2; }
```

Ancak iki ayrı capabilities frame'i yerine **paylaşılmış tek frame tercih
edilir** — 0003 yazarıyla koordinasyon: "RESUME_V1 bit'ini rezerv edin,
biz 0004'te tanımlamayacağız". Koordinasyon tamamlanana kadar `0003-chunk-hmac.md`
açık sorular bölümüne "RESUME_V1 = 0x0002 bit'i 0004 RFC tarafından talep
edildi; paylaşılmış enum'a ekleyin" notu düşer (bu RFC merge edilirken
PR açıklamasında hatırlatılır).

## 5. Alternatifler

### 5.1 HTTP Range semantics
LocalSend HTTP `Range: bytes=N-` header'ı ile resume yapıyor. **Reddedildi:**
Quick Share tamamen TCP stream tabanlı, HTTP katmanı yok, kendi payload
framing'i var. Range semantiği upstream'e uymak Quick Share'i kırar.

### 5.2 Chunk-başına checkpoint
Her chunk'tan sonra `.meta`'ya fsync. **Reddedildi:** 10 GiB / 512 KiB chunk =
20,480 fsync → NVMe'de bile 60+ sn overhead. Onun yerine **her 16 chunk'ta
bir** (8 MiB) checkpoint fsync; resume'da en kötü 8 MiB tekrar indirilir.
Bu rakam `config.resume.checkpoint_interval_chunks` ile tunable.

### 5.3 Kalıcı, peer-bağımsız content-hash indeksi
"Aynı content-hash'e sahip dosya tekrar geliyorsa hiç indirme" (content-addressed
dedup). **Reddedildi:** Threat model'e yeni side-channel açıyor (peer X'in
hangi dosyaları önceden aldığını peer Y sorgulayabilir), implementasyon
karmaşık, v0.8 scope'u dışı.

### 5.4 Rsync rolling hash
Değişmiş byte'ları patch'le. **Reddedildi:** HekaDrop resume senaryosu
"dosya aynı, sadece transfer yarıda kesildi" — byte'lar değişmedi. Rsync
semantik overkill; SHA-256 equal check yeterli.

## 6. Geriye uyumluluk ve migration

- **Eski peer (v0.7.x)** capabilities frame göndermez → sender RESUME_V1
  bit'ini görmez → resume yolu **asla denenmez**, bugünkü akış (tam restart)
  korunur.
- **Yeni sender, eski receiver**: sender Introduction sonrası
  `ResumeHint` bekler ama receiver göndermez. Sender **2 saniye timeout**
  sonra normal akışa geçer (offset=0). Timeout değeri `RESUME_HINT_TIMEOUT_MS`
  sabiti; config'te override edilebilir.
- **Feature flag**: v0.8.0'da default **açık**. Config'te
  `resume.enabled: bool` ile disable edilebilir (paranoya / bug workaround için).
- **Proto versioning**: `proto/v1/` (mevcut) dokunulmaz; `proto/v2/resume.proto`
  yeni dosya olarak eklenir. Build zamanı cargo feature flag'lemez; v1+v2
  aynı binary'de yan yana.

## 7. Güvenlik değerlendirmesi

Threat model (`docs/security/threat-model.md`) TB-3 (App ↔ Peer) ve TB-5
(App ↔ Filesystem) sınırlarını etkiler.

| Saldırı | Risk | Mitigation |
|---------|------|------------|
| Partial file enumeration (local başka user) | Orta | `~/.hekadrop/partial/` mode `0700`, dosyalar `0600`; Linux/macOS'ta POSIX perm + Windows ACL "Owner only" |
| Session hijack via forged `session_id` | Düşük | `session_id` UKEY2 auth_key'den derive; attacker predict edemez (128-bit ECDH shared secret'ten) |
| Partial_hash fingerprinting | Düşük | `ResumeHint` yalnız **mevcut valid session**'da gönderilir; sender sadece kendi Introduction'ına cevap olarak alır. Attacker "bu cihazda X dosyası var mı" sorgulayamaz çünkü Introduction olmadan hint kabul edilmez |
| Symlink race (`partial/` içinde attacker symlink koyar) | Düşük | Dosya açma `O_NOFOLLOW` (Linux), `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` negate (Windows); meta okuma path canonicalize + `starts_with(partial_dir)` kontrol |
| TOCTOU: attacker `.part` bytes'ını flip, partial_hash receiver'da tutarlı ama sender `[0..offset]` farklı | **DOĞAL** | `partial_hash` mismatch → `ResumeReject` → receiver `.part` + `.meta` silip byte 0'dan başlar. Saldırgan corruption gerçekleştirse bile data yenisini alır (sadece resume avantajı kaybolur) |
| Disk fill DoS (attacker 5 GiB partial yaratır) | Düşük | Budget + LRU; ayrıca per-peer rate limit (`src/state.rs:89-127`) mevcut. Kullanıcı consent'siz kimse partial yazamaz |
| Partial-leak via crash dump | Çok düşük | `.part` dosyaları şifrelenmemiş **payload plaintext** içerir — bu mevcut davranış, yeni risk değil. Dokümana ekle: "Shared makinede hassas dosya paylaşımı yapılıyorsa `~/.hekadrop/partial/` dizini sensitive, kullanıcı disk encryption açmalı" |

**Yeni attack surface?** Evet, ama kontrollü: `ResumeHint` frame parser'ı
yeni bir giriş noktası. Fuzz harness `fuzz_resume_hint_parse` (ROADMAP
satır 196'da zaten listeli) v0.9.0 fuzzing sprint'inde aktive edilir.

## 8. Performans değerlendirmesi

| Metric | Bugün | Resume ile | Açıklama |
|--------|-------|------------|----------|
| Kesik 10 GiB sonrası re-transfer | 20 dk (tüm dosya) | 30 sn hash + kalan %X | SHA-NI'siz; chunk-HMAC ile <1 sn |
| Resume olmadan bandwidth | 100% re-download | 100% re-download | Değişmedi |
| Resume ile bandwidth (başarılı) | — | Kalan offset kadar | ~%92 transfer'den sonra sadece %8 |
| Receiver disk I/O | Chunk write | +`.meta` update her 16 chunk | ~%1 overhead |
| Sender CPU (resume verify) | 0 | SHA-256 `[0..offset]` | 30 sn / 10 GiB |
| Memory | ~1 MiB/connection | +128 byte/session (meta cache) | İhmal edilebilir |

Hot path etkisi minimal: normal (resume-miss) akışta ek overhead **tek
RESUME_HINT_TIMEOUT bekleyiş** (eski peer'larla 2 sn'lik geç başlangıç).
v0.8 capabilities bit ile bu timeout eski peer'lar için tetiklenir; yeni
peer'lar capabilities negotiation ile anında "resume yok" sinyali verir.

## 9. Test planı

**Integration:**

1. `test_resume_happy_path`: 1 GiB dosya üret; sender + receiver loopback;
   50. chunk'ta receiver socket kill; sender tarafında 500 ms bekle, yeniden
   bağlan; receiver `.meta` mevcut → ResumeHint gönder → sender seek → transfer
   tamam; final dosya SHA-256 eşit.
2. `test_resume_hash_mismatch`: Aynı senaryo + disconnect sonrası receiver
   `.part`'ın ortasındaki bir byte'ı flip; yeniden bağlan; sender hash
   karşılaştırma fail → `ResumeReject` → receiver partial sil → byte 0'dan
   restart → sonuç final dosya doğru.
3. `test_resume_expired_ttl`: `.meta.updated_at` 8 gün önce; cleanup sweep
   çalıştır; `.part` silindi; yeni handshake → resume yok, byte 0'dan.
4. `test_resume_budget_lru_eviction`: `partial/` dir'de 6 GiB'lık partial'lar;
   cleanup sweep; en eski olanlar 5 GiB'a düşene kadar silinir.
5. `test_resume_capabilities_old_peer`: Mock receiver capabilities
   göndermez; sender 2 sn timeout → byte 0'dan.

**Unit:**

6. `session_id_i64_deterministic`: Aynı auth_key → aynı i64.
7. `partial_hash_calculation_streaming_matches_one_shot`: 100 MiB rastgele
   buffer; streaming (1 MiB parça) SHA-256 = tek seferlik SHA-256.
8. `resume_hint_frame_roundtrip`: Encode → decode; fields eşit.
9. `partial_cleanup_skips_in_use_sessions`: Aktif session kayıtlı; cleanup
   onu silmemeli.
10. `partial_path_traversal_reddedilir`: `session_id = "../../etc"` içeren
    meta → parser reject.

**Fuzzing:** `fuzz_resume_hint_parse` (protobuf-derived frame'in random
byte input ile panic-free decode'u).

## 10. Dokümantasyon etkisi

- `README.md` — "v0.8 özellikleri" bölümüne "Transfer Resume" maddesi ekle.
- `CHANGELOG.md` — v0.8.0 entry.
- `docs/protocol/resume.md` — **bu RFC ile aynı PR'da** merge olacak wire spec.
- `docs/security/threat-model.md` — §3 assets'e `~/.hekadrop/partial/`
  eklenir; §TB-5 satırlarına resume notu.
- `docs/architecture.md` — PayloadAssembler diagramı güncel.

## 11. Efor kırılımı

| # | İş | Süre |
|---|----|-----:|
| 1 | `proto/v2/resume.proto` tanım + build.rs entegrasyon | 2 s |
| 2 | `session_id_i64` helper + test | 1 s |
| 3 | `.meta` JSON struct + serde + read/write + atomic rename | 4 s |
| 4 | Partial dir creation + perms (Unix chmod, Windows ACL) | 3 s |
| 5 | `PayloadAssembler` meta yazma (her 16 chunk + finalize) | 4 s |
| 6 | Receiver: Introduction sonrası `.meta` lookup + `ResumeHint` send | 3 s |
| 7 | Sender: `ResumeHint` parse + hash verify + seek + `send_file_chunks(start_offset)` | 5 s |
| 8 | `ResumeReject` frame + mismatch cleanup | 2 s |
| 9 | Capabilities bit koordinasyonu (RFC-0003 ile) | 1 s |
| 10 | Cleanup sweep + budget LRU | 4 s |
| 11 | OS scheduler template'leri (systemd/launchd/Windows Task) | 3 s |
| 12 | Integration testleri (5 adet) | 6 s |
| 13 | Unit testleri (5 adet) | 3 s |
| 14 | Fuzz harness iskeleti | 2 s |
| 15 | Dokümantasyon (README + CHANGELOG + protocol/resume.md peer-review) | 3 s |
| | **Toplam** | **~46 saat (≈ 1 hafta)** |

## 12. Açık sorular

1. **Cleanup tetikleyici önceliği:** Startup-only yeterli mi (tray uzun
   çalışır), yoksa OS scheduler şart mı? Önerim: **her ikisi**, çünkü
   kullanıcı başlatmayı unutursa scheduler bekçi görevi görür.
2. **Disk budget default:** 5 GiB uygun mu? Mobil laptoplarda 256 GB SSD
   düşünüldüğünde %2. Alternatif: disk free'ye göre dinamik (`min(5 GiB,
   free * 0.05)`).
3. **Chunk checkpoint aralığı:** 16 chunk (8 MiB) iyi trade-off mı? NVMe'de
   32 chunk bile asenkron fsync ile maliyetsiz. Bench ile karar.
4. **Trust gating (`resume_require_trusted`):** Default false haklı mı?
   Güvenlik-paranoid kullanıcılar için UI toggle.
5. **Resume UI affordance:** Kullanıcı "bu %92 partial var, devam et/sıfırla"
   seçebilsin mi, yoksa otomatik resume tercih edilsin mi? Önerim: otomatik
   (sessiz) + Settings > Diagnostics'te partial list görünür + manual delete.
6. **Capabilities frame ownership:** RFC-0003'te mi, burada mı tanımlanacak?
   Koordinasyon gerekir.
7. **Klasör payload'ları:** RFC-0005 folder streaming için resume nasıl
   çalışır? Per-file mi (her dosya bağımsız partial), yoksa folder manifest
   seviyesinde mi? Önerim: **per-file**. RFC-0005 paralel yazılırken bu
   notu reviewer'a geçir.

## 13. Referanslar

- `docs/ROADMAP.md` v0.8.0 §"Transfer resume" (satır 122-124), erişim 2026-04-24.
- `docs/rfcs/0003-chunk-hmac.md` (paralel, henüz merge edilmemiş).
- `docs/rfcs/0005-folder-payload.md` (paralel).
- `docs/security/threat-model.md` TB-3, TB-5.
- LocalSend resume protocol: https://github.com/localsend/localsend/blob/main/documentation/protocol-v2.md (erişim 2026-04-24).
- rquickshare partial handling: https://github.com/Martichou/rquickshare (erişim 2026-04-24).
- IETF RFC 7233 (HTTP Range) — karşılaştırma için, bizim modelin alternatifi, erişim 2026-04-24.
- NIST FIPS 180-4 (SHA-256).
- `src/sender.rs::send_file_chunks` (mevcut implementation), `src/payload.rs::PayloadAssembler` (GC + partial handling).
