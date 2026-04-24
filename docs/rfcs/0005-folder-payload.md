# RFC 0005 — Folder Payload

- **Başlatan:** @maintainers
- **Durum:** Draft
- **Oluşturulma tarihi:** 2026-04-24
- **Hedef sürüm:** v0.8.0
- **İlgili issue:** —
- **İlgili RFC'ler:** 0003 (chunk-HMAC, capabilities frame), 0004 (transfer resume)

---

## 1. Özet

HekaDrop bugün klasörü drag-drop eden kullanıcıya *flat* bir çoklu-dosya gönderim
deneyimi veriyor: `src/sender.rs` recursive walk yapıyor, her dosya için ayrı
`FileMetadata` üretiyor, tek bir `Introduction` içinde N metadata birden
yolluyor. Alıcı tarafta bu N dosya `~/Downloads/` içine *flat* düşer; dizin
yapısı, ortak klasör adı, aralarındaki bütünlük ilişkisi kaybolur. Bu RFC, Quick
Share wire format'ını kırmadan klasör semantiğini taşıyan bir **FolderPayload**
tipi önerir: receiver'ın gözünde tek bir `FILE` payload — ancak MIME marker'ı
`application/x-hekadrop-folder` — içinde tar-benzeri *custom binary* bir bundle
(`HEKABUND` magic + length-prefixed JSON manifest + concatenated file data)
taşınır. Her iç dosya için ayrı SHA-256, manifest bütünlüğü için bundle-level
SHA-256, hot path için RFC-0003 chunk-HMAC stacking ile entegre. Receiver
`~/Downloads/.hekadrop-temp-<session>/` altına stream eder ve bitince atomic
rename ile görünür hâle getirir. Eski peer'lara fallback: flatten + multiple
FILE (bugünkü davranış), capabilities frame'deki `folder_v1` biti ile müzakere
edilir.

## 2. Motivasyon

**Senaryo 1 — Aile fotoları:** "Geçen yaz tatilinden 50 fotoyu telefonuna at"
diyorsunuz. Bugün alıcıda 50 ayrı bildirim + 50 dosya `Downloads` içinde dağılıyor;
ortak `tatil-2025/` klasörü kayboluyor. NearDrop'un [issue
#211](https://github.com/grishka/NearDrop/issues/211) iki yıldan uzun süredir
açık; rquickshare ve LocalSend de klasör semantiğini *folder path* alanıyla
işaretlemiyor (LocalSend ayrı request per file yapar). Çözümü 0. günden
kendimize yazarsak v0.8 cutoff'unu kaçırmayız.

**Senaryo 2 — Web dev → telefon:** Developer `~/projects/landing-page/` klasörünü
telefondaki tarayıcıda açılacak şekilde göndermek istiyor. Klasör yapısı
(`index.html`, `assets/css/…`, `assets/img/…`) korunmazsa göreli linkler kırılır.

**Senaryo 3 — İç içe klasör derinliği:** `~/Documents/vergi-2025/Q1/…`,
`Q2/…`. 3+ seviye iç içe yapılar bugün flat gelirse isim çakışmaları ve
manuel yeniden organize etme maliyeti doğar.

**Mevcut kod yetersizliği:** `src/sender.rs:905-935` `build_introduction_multi`
planları `FileMetadata` array'i olarak paketler. `FileMetadata.parent_folder`
alanı proto'da (`proto/wire_format.proto:63`) mevcut ama receiver'da yoksayılır
— ayrıca path traversal vektörü olduğu için güvenle kullanılabilmesi için per-
segment sanitize gerekir. Yani "parent_folder'ı canlandır" seçeneği bile bu
RFC'nin yaptığının küçük bir altkümesi (bundle integrity, atomic rename,
symlink policy vb. yine bizim işimiz).

## 3. Ayrıntılı tasarım

### 3.1 Wire seviyesi — mevcut Quick Share format'ı korunur

Klasör, receiver'a `IntroductionFrame` içinde **tek** `FileMetadata` olarak
görünür:

```
FileMetadata {
  name:         "tatil-2025.hekabundle",   // iç formatın ismi
  type:         UNKNOWN,
  payload_id:   <i64>,
  size:         <bundle toplam byte sayısı>,
  mime_type:    "application/x-hekadrop-folder",
  id:           <i64 attachment id>,
  parent_folder: "",
  // --- HekaDrop uzantısı (aşağı bakın) ---
  attachment_hash: <manifest SHA-256 ilk 8 byte i64 olarak>,
}
```

MIME marker `application/x-hekadrop-folder` **ayırt edici**: peer `folder_v1`
capability reklam ettiyse bu MIME'ı bundle olarak açar; etmediyse dosyayı ham
olarak kaydeder — ama zaten `folder_v1` yoksa sender fallback'e geçer (§3.6).
`attachment_hash` alanı proto'da 64-bit opak; biz bundle manifest SHA-256'sının
ilk 8 byte'ını network-endian big-endian int64 olarak yerleştiririz. Bu,
introduction-time integrity pre-commit sağlar: peer manifest'i receive edince
karşılaştırır, eşleşmezse bundle reddedilir (§3.5).

### 3.2 İç format — `HEKABUND` v1

Bundle, receiver `PayloadAssembler` (bkz. `src/payload.rs:113+`) tarafından
`FileSink` aracılığıyla diske yazılır; yazım bittikten sonra sync olarak
deserialize edilir (stream-parse değil; MVP'de basitlik > latency). Layout,
offset 0'dan itibaren:

```
offset  size       alan                         açıklama
------  ---------  ---------------------------  --------------------------------
0       8          magic                        ASCII "HEKABUND"
8       4          version (u32 BE)             0x0000_0001
12      4          manifest_len (u32 BE)        N byte, JSON UTF-8 uzunluğu
16      N          manifest_json                serialize edilmiş manifest
16+N    M          concat_file_data             manifest sırasıyla append
16+N+M  32         bundle_sha256                magic..concat_file_data üzerinde
                                                hesaplanmış SHA-256 (trailer)
```

Trailer SHA-256 `bundle_sha256` **manifest + dosya datası + magic + version**
bütününü kapsar. Manifest tampering veya data swap tespit edilir.
`manifest_len` maksimum `8 MiB` — 10k dosya × ~600 byte kayıt rahatça sığar;
bu üstüne çıkarsa reddedilir (DoS limiti).

**Manifest JSON schema (v1):**

```jsonc
{
  "version": 1,
  "root_name": "tatil-2025",          // receiver klasör adı (sanitize edilir)
  "created_utc": "2026-04-24T12:34:56Z",
  "entries": [
    {
      "type": "file",
      "path": "IMG_0001.jpg",          // root-relative, POSIX separator
      "size": 3145728,
      "sha256": "<hex 64>",
      "mode": 420,                     // opsiyonel, POSIX mode (decimal)
      "mtime_utc": "2025-07-15T14:02:11Z"  // opsiyonel
    },
    {
      "type": "directory",
      "path": "albums/istanbul"
    },
    // symlink girişi YOK (§3.4)
  ]
}
```

Parser strict: unknown **top-level** field ignore; unknown **entry** field
ignore; bilinmeyen `type` degeri → tüm bundle reject. `path` alanı ASCII
`/` separator; Windows'ta `\` içerir gelirse reject. `path` her segment için
`sanitize_received_name` muadilinden geçirilir (§3.5).

### 3.3 Maksimum sınırlar

| Sınır | Değer | Gerekçe |
|---|---|---|
| `manifest_len` | 8 MiB | 10k dosya × ~600 byte + slack |
| Dosya sayısı / bundle | 10 000 | DoS (open-file deskriptör, inode basınç); tipik tatil-klasörü <1000 |
| Per-file size | `i64::MAX` | `FileMetadata.size` ile aynı clamp (mevcut `file_size_guard`) |
| Toplam bundle size | `i64::MAX` (1 TiB praktik) | `PayloadTransferFrame.total_size` |
| Dizin derinliği | 32 | `..`/symlink saldırılarına karşı ek tabula |
| Path segment uzunluğu | 200 byte (mevcut sanitizer sınırı) | `connection.rs:1056` ile tutarlı |

10k seçimi: LocalSend'in pratik limiti yok ama CI testlerinde >5k dosyada OS
limit'i (macOS `ulimit -n` default 256–2048) sürekli patlıyor; 10k bize 3–4×
headroom verir.

### 3.4 Symlink ve özel dosya davranışı

**Sender tarafı:**

- `std::fs::symlink_metadata` ile entry tipi tespit edilir (resolve etmeden).
- Symlink → **skip**, `warn!` log'a basılır (`src/log_redact::path_basename`
  ile redact), kullanıcı UI'a toplu özet: "3 symlink atlandı."
- Regular file → bundle'a dahil.
- Directory → recurse + `type: "directory"` entry (boş klasörler dahil).
- Pipe, socket, block/char device → skip + warn.

**Receiver tarafı:**

- Manifest'te `type: "symlink"` **yok** (sender yazmaz). Gelirse → bundle reject.
- Her `path` her segmentte `sanitize_received_name` uygulanır; `..`, absolute
  path, Windows reserved, NUL/control karakterler reject.
- Dosya yazmadan önce parent directory `create_dir_all` + `symlink_metadata`
  kontrol: parent symlink ise bundle reject (TOCTOU guard, `payload.rs:349-360`
  paterninin klasör genellemesi).

Alternatif (reddedildi): Relative symlink'i target-içinde kalıyorsa takip et →
MVP'nin 5× karmaşıklığı; v0.9+ ayrı RFC.

### 3.5 Path sanitization katmanı

`src/connection.rs:1006-1065` `sanitize_received_name` *basename-only*
çalışıyor. Folder payload'ı için **per-segment** bir wrapper ekleyeceğiz
(aynı dosyaya, isim: `sanitize_received_relative_path`):

```
fn sanitize_received_relative_path(raw: &str) -> Result<Vec<String>, PathErr>
```

Davranış:

1. `raw.split('/').map(sanitize_received_name)` — her segment ayrı ayrı
   mevcut kurallardan geçer.
2. Segment `"."` → skip. Segment `".."` → `PathErr::Traversal` (reject; mevcut
   `sanitize_received_name` bunu `"dosya"`a çevirir, klasörde bu yetmez
   çünkü sessizce yer değiştirir).
3. Segment listesi boş → `PathErr::Empty`.
4. Derinlik >32 → `PathErr::TooDeep`.

Bundle-level integrity: manifest SHA-256 `attachment_hash` ile introduction'a
commit edildiğinden, alıcı manifest'i parse etmeden önce bundle_sha256 trailer
doğrular; trailer geçerse manifest de güvenilir kabul edilir. Per-file SHA-256
yine de dosya yazımı sırasında streaming olarak hesaplanır; **herhangi bir
dosyanın SHA-256 mismatch'i → tüm bundle reject** (atomic-reject politikası;
§3.6 state machine'i buna göre tanımlıdır). "49/50 doğru" gibi kısmi kabul
senaryosu desteklenmez; kullanıcıya yanlış güven vermemek + receiver state
machine'i basit tutmak için bu karar verildi.

### 3.6 Atomic rename ve receive state machine

Receiver flow (`src/connection.rs` dispatch + `src/payload.rs` assembler):

1. Introduction'da `application/x-hekadrop-folder` MIME + `folder_v1`
   capability → `PayloadAssembler::register_file_destination` ile
   `~/Downloads/.hekadrop-temp-<session_id>.bundle` dosyası rezerve edilir
   (`unique_downloads_path` ile; mevcut `OpenOptions::create_new(true)`
   guard'ı aynen geçerli).
2. Payload bitince trailer SHA-256 doğrulanır. Uyuşmazsa temp silinir, UI error.
3. `manifest_json` parse. `root_name` sanitize edilir → `safe_root`.
4. `~/Downloads/.hekadrop-temp-<session_id>/` oluşturulur (`create_new` klasör;
   Unix'te `mkdir` EEXIST race ile idempotent değildir, burada session-id
   unique olduğu için problem yok).
5. Manifest entries sırayla extract (stream; in-place into
   `.hekadrop-temp-<session_id>/`):
   - `type: "directory"` → `create_dir_all` (sanitize path).
   - `type: "file"` → path açılır (`create_new` flag), parent symlink kontrol
     sonra bundle'dan `size` byte kopyalanır; streaming SHA-256 hesaplanır.
     **Herhangi bir dosyada mismatch → atomic reject:** `.hekadrop-temp-<session_id>/`
     dizini ve `.bundle` dosyası tamamen silinir, receiver UI "bundle reddedildi:
     dosya `<path>` integrity kontrolünü geçemedi" hatası gösterir, `stats.json`'a
     abort kaydedilir. **Kısmi kabul yok**; "49/50 doğru" senaryosunda bile tüm
     bundle atılır.
6. Tüm entry'ler başarılı extract edildiyse → `unique_downloads_path(&safe_root)`
   ile hedef isim seçilir (çakışmada `tatil-2025 (2)`), temp dizini `rename`
   ile hedefe taşınır. `rename` cross-device EXDEV olursa fallback: recursive
   copy + delete.
7. Bundle dosyası (`.bundle`) silinir.

**Atomic-reject gerekçesi:** (a) receiver state machine basit kalır — tek
"commit" noktası, partial cleanup yolları yok; (b) kullanıcıya yanlış güven
verme riski yok (kısmi kabul "klasörün tamamı geldi" illüzyonu yaratır);
(c) corrupted sender veya MITM senaryosunda "eksik dosya var mı?" sorusunu
kullanıcıya yıkmaktan kaçınır; (d) resume (§3.9) bundle'ı yeniden denemeye
olanak tanıyacağından kullanıcı için pratikte maliyet sınırlı.

### 3.7 Capabilities müzakeresi (RFC-0003 entegrasyonu)

Kanonik `Capabilities` mesajı RFC-0003 §3.2'de tanımlı; bu RFC yalnız kendi
bit'ini talep eder. Feature bitleri (üç RFC ortak sabit tablosu):

```
CHUNK_HMAC_V1    = 0x0001   (RFC-0003, bit 0)
RESUME_V1        = 0x0002   (RFC-0004, bit 1)
FOLDER_STREAM_V1 = 0x0004   (bu RFC,   bit 2)
0x0008..0x8000   — reserved for v0.8–v1.0
```

Ayrıca `FolderManifest` mesajı (in-bundle manifest JSON'unu wire'da
reprezente eder; bkz. §3.2) `HekaDropFrame.folder_mft = 14` slot'unu
kullanır. Quick Share upstream `V1Frame.FrameType` enum'una dokunulmaz.

Sender `FOLDER_STREAM_V1` peer'da set değilse:
- Fallback path: bundle oluşturma. `build_introduction_multi` ile flat gönderim
  (bugünkü kod). Log: `warn!("[sender] peer folder_v1 desteklemiyor, flat gönderim")`.
- Kullanıcıya UI'da discrete bir uyarı: "Bu alıcıda klasör yapısı korunmayacak."

### 3.8 Chunk-HMAC stacking (RFC-0003 entegrasyonu)

RFC-0003 chunk-HMAC bundle'ın **wire level** chunk'larına uygulanır — yani
`PayloadTransferFrame` içindeki bytes'a. Bundle'ın *iç* SHA-256 kontrolü
(per-file + trailer) bundan bağımsız: chunk-HMAC koparılmış wire'ı tespit
eder; iç SHA-256 sender disk'ten bundle oluştururken corruption'a veya
kötü niyetli sender'a karşı korur. Double-check maliyeti ~%1 (chunk-HMAC
zaten olacak; iç SHA-256 sender'da dosya okuma sırasında 0-cost, receiver'da
stream-compute).

### 3.9 Resume (RFC-0004 entegrasyonu)

RFC-0004 resume, file-granularity önerir: bundle içinde yarım kalmış dosya
bir sonraki resume'da **baştan** değil, kaldığı yerden. Bunun için bundle iç
yapısı manifest sırasını garanti eder — receiver `partial/<session_id>/`
altında hem `.bundle` temp'ini hem de `progress.json` tutar:

```json
{ "entries_completed": 23, "current_entry_offset": 1048576 }
```

Resume gelince sender `ResumeHint { payload_id, offset: 16+N+<file_offset> }`
ile byte-level devam eder. Manifest seek pozisyonu anlık olarak bilindiği için
bu doğrudan haritalanır. TTL 7 gün — roadmap'teki kural aynı.

### 3.10 UX

**Sender:**
- Drag-drop folder → tray menüde iki seçenek: *Send as folder (default)*
  veya *Send as individual files*. Tercih per-session, "remember" yok (MVP).
- CLI yok (v0.8 tray app).

**Receiver:**
- Accept dialog yeni metin: "`{peer}` cihazından `{root_name}` klasörü — N
  dosya, X MB. Kabul edilsin mi?" — mevcut `ui.rs` dialog'unun bir varyantı.
- Progress: toplam byte + "dosya 23/50" her dosya tamamlanınca güncellenir.
- Completion notification'ında "Klasörü Aç" aksiyonu → platform `reveal`
  (macOS Finder `open -R`, Windows `explorer /select,`, Linux best-effort
  `xdg-open` parent).

## 4. Alternatifler

**A. Flat rename convention (`name = "tatil/photo1.jpg"`)** — FileMetadata
`name` field'ına `/` koyup receiver'da parse. Reddedildi: (1) `sanitize_received_name`
zaten `/` filtreliyor (`connection.rs:1023`), bypass için kod değişikliği
gerek; (2) Windows `\` ile tutarsızlık; (3) atomic rename yok, partial delivery
yarım klasör bırakır; (4) manifest bütünlüğü yok — tek dosya corrupt olursa
diğerleri zehirlenmiş kabul edilir mi belirsiz.

**B. Standart tar (`tar` crate)** — Reddedildi: `tar` crate 180+ KB bağımlılık
ekler (`hekadrop-core` minimalizm ilkesi, RFC dependency-policy). Sparse files,
GNU/POSIX tar header farkları, UStar vs PAX uzantıları — maintenance kuyruğu.
Kontrolü bize dışarı çıkarır. Özel binary format 200 satır Rust; tar parser
3k satır.

**C. ZIP** — Sıkıştırma opsiyonel gelse bile deflate-bomb vektörü ve entry-level
encryption karmaşası MVP dışı. Sıkıştırma ayrı RFC (v0.9+).

**D. Her dosya için ayrı payload + grouping metadata field** — `parent_folder`
alanı (`wire_format.proto:63`). Reddedildi: introduction'da N metadata göndermek
zorunda, atomic rename'e introduction-level semantik gerekir, receiver "klasör
tamamlandı mı?" sorusunu her dosyanın SHA-256'sı üzerinden mark-off map tutarak
cevaplar — karmaşıklık bundle'dan az değil, üstelik partial-introduction
(sender yarıda düşerse) recovery belirsiz.

**E. Bundle'ı sender diskte oluştur, sonra normal FILE payload gibi yolla**
(reddedildi *bu RFC'de değil*, ama tasarım kararı belirginleştirmek için):
biz bundle'ı **bellekte streaming** oluşturuyoruz (`src/sender.rs::send_file_chunks`
paterni genişletilir). Disk'e tar yaz → diski 2× şişirir, 50 GB klasörde
kullanıcı diski dolar. Streaming daha iyi.

## 5. Geriye uyumluluk ve migration

- Eski peer (`folder_v1` yok) → sender fallback flatten. Alıcı hiçbir kod
  değişikliği görmez; bugünkü davranışın aynısı.
- Quick Share Android / Chrome ile interop: Android zaten folder desteklemez;
  sender `folder_v1` yokluğunu peer signature'ından (endpoint_id prefix'i)
  değil capabilities frame'inden anlayacak — yani Android peer her durumda
  flatten alır. Introduction formatı Quick Share uyumlu kalır.
- Mevcut testler (`src/sender.rs` integration) folder path'ini test etmiyor;
  yeni testler ekleyeceğiz, eski testler etkilenmez.
- Feature flag: `HEKADROP_FOLDER_V1=0` env ile kapatılabilir (debug amaçlı).
  Production default: açık.

## 6. Güvenlik değerlendirmesi

| Vektör | Mitigation |
|---|---|
| Path traversal (`../etc/passwd`) | Per-segment `sanitize_received_relative_path`, `..` → reject |
| Absolute path (`/etc/passwd`) | Manifest `path` leading `/` → reject parse |
| Symlink race (parent temp) | Write-time `symlink_metadata` parent check |
| Zip-slip equivalent | Bundle iç path'leri root-relative olarak kilitlenir, `create_new` open flag |
| Manifest injection | Strict JSON, unknown entry-type reject, manifest_len ≤ 8 MiB |
| Resource exhaustion (çok dosya) | 10 000 entry cap, >8 MiB manifest reject |
| Resource exhaustion (derinlik) | Depth 32 cap |
| Partial bundle poisoning | Trailer bundle SHA-256; uyuşmazsa temp silinir |
| Per-file corruption (malicious sender) | Entry SHA-256 mismatch → **atomic reject**: `.hekadrop-temp-<session>/` komple silinir, hiçbir dosya `~/Downloads/`'a taşınmaz, UI net hata |
| Disk doldurma (sender kötü niyetli) | Receiver disk quota check v0.8.1'e ertelendi — açık soru |
| TOCTOU rename | `rename` atomic aynı FS üzerinde; cross-device fallback copy-delete sırasında hedef `create_dir_all` + `create_new` guard |

Threat model dokümanı `docs/security/threat-model.md` §7.1 (Path Traversal) ve
§7.3 (Symlink Race) bölümleri bu RFC sonrası güncellenecek: per-segment
sanitize çağrısı STRIDE tablosuna eklenir, bundle-level depth limit not düşer.

Yeni crypto primitive **yok** — SHA-256 ve AES-GCM mevcut stack (`src/secure.rs`)
üzerinden geliyor; audit yüzeyi sabit.

## 7. Performans değerlendirmesi

| Metrik | Etki | Not |
|---|---|---|
| Manifest overhead | ~600 byte/dosya × 10k = 6 MB worst case | 10k dosya senaryosunda %0.01 overhead (TB-scale) |
| Sender CPU | Per-file SHA-256 | Zaten yapılıyor; bundle yapımı ek ~5 ns/byte append |
| Receiver CPU | Bundle trailer SHA-256 + per-file SHA-256 | Stream-compute, disk I/O'ya paralel; bottleneck I/O |
| Bellek | Bundle stream, manifest ≤ 8 MiB yüklenir | Konstant; dosya verisi diske direkt akar |
| Latency (küçük klasör) | Bundle wrap ~5-10 ms | Introduction'dan önce manifest hash hesaplanır |
| Disk (sender) | Ek disk **yok** — streaming | Kritik fark: tar crate disk'e yazar, biz yazmayız |
| Throughput | Chunk-HMAC ile birlikte ~%5 overhead | RFC-0003'ten |

Hot path: receiver `ingest_file` chunk yazımı. Bundle için değişiklik: trailer
buffer'ı son 32 byte'ı holdback et, rest'i disk'e yaz; payload tam gelince
trailer'ı doğrula. Net ek: 0.

## 8. Test planı

**Unit:**
- `sanitize_received_relative_path`: traversal, absolute, unicode, reserved,
  depth limit, empty segment edge case'leri.
- Manifest serde: round-trip, unknown field, malformed JSON, oversized,
  bilinmeyen entry type reject.
- Bundle trailer: doğru hash geçer, 1-bit flip yakalanır.

**Integration:**
- 100 dosyalı klasör roundtrip; SHA karşılaştırmaları.
- İç içe 5 seviye klasör, tüm yapı korunur.
- Boş klasör: manifest'te directory entry var, receiver yaratır.
- 1 dev dosya (5 GiB) — streaming limit testi.
- Aynı ad çakışması: `~/Downloads/foo/` zaten varsa `foo (2)/` alınır.

**Edge:**
- Symlink dolu klasör sender atlar, manifest'te görünmez.
- Windows path separator `\` — sender POSIX'e normalize eder.
- Unicode emoji/RTL dosya adları.
- Manifest tampering (trailer yeniden hesapla, data swap) → trailer yakalar.

**Attack fuzz:**
- `fuzz/` altına `fuzz_bundle_parser.rs` hedefi: manifest + bundle layout
  fuzzing. Traversal/injection vektörleri oss-fuzz'a eklenir (roadmap §198).

**Interop:**
- Android Quick Share ile test: `folder_v1` yok → flatten fallback'in
  beklendiği gibi çalıştığı doğrulanır.

## 9. Dokümantasyon etkisi

- `README.md` özellik listesi: "klasör gönderimi (dizin yapısını korur)".
- `docs/ROADMAP.md` v0.8.0 bölümü: folder streaming checkmark.
- `docs/security/threat-model.md` §7.1 ve §7.3: bundle path-sanitize ve
  derinlik limiti notu.
- `CHANGELOG.md`: "Added: folder payload (RFC-0005)".
- `docs/rfcs/README.md` RFC index tablosuna satır.

## 10. Efor kırılımı

| Adım | Tahmini efor | Dosyalar |
|---|---|---|
| `sanitize_received_relative_path` + testler | 3 saat | `src/connection.rs`, test bloğu |
| Bundle serializer (sender stream) | 6 saat | `src/sender.rs` (yeni `bundle.rs` submodule) |
| Bundle deserializer + extract state machine | 8 saat | `src/payload.rs` genişletme |
| Capabilities frame `folder_v1` hook | 2 saat | RFC-0003 PR'ıyla sync, 1 satır bit |
| Fallback flatten path glue | 2 saat | `src/sender.rs` dispatcher |
| UI accept dialog varyantı | 3 saat | `src/ui.rs`, i18n key'leri (tr/en) |
| Progress entegrasyonu | 3 saat | `src/progress.rs` (varsayılan) |
| Atomic rename + temp cleanup | 3 saat | `src/payload.rs` + platform-specific EXDEV |
| Integration testler | 6 saat | yeni `tests/folder_payload.rs` |
| Fuzz target | 2 saat | `fuzz/` |
| Dokümantasyon güncellemeleri | 2 saat | README, threat-model, CHANGELOG |

**Toplam:** ~40 saat (≈1 hafta dedicated). v0.8.0 2026-07-31 hedefiyle tutarlı.

## 11. Açık sorular

1. **POSIX mode korunsun mu?** Windows→Unix yönünde default `0644`/`0755`,
   Unix→Windows yönünde mode yok sayılır. Unix→Unix'te manifest'ten oku. MVP
   öneri: **yaz ama yok sayılabilir** — `mode` manifest alanı opsiyonel,
   receiver platformu uygulayamıyorsa ignore. Karar verilecek: mode alanı
   zorunlu mu yoksa opsiyonel mi?

2. **mtime korunsun mu?** UX için faydalı (fotograflar chronological kalır)
   ama implementation maliyeti düşük. Öneri: **yaz ve uygula**; platformda
   desteklenmezse ignore.

3. **Symlink policy kesin skip mi yoksa reject-whole-folder opsiyonu mu?**
   Öneri: **skip + toplu UI uyarısı**. Alternatif: UI prompt ("N symlink bulundu,
   atlansın mı?") — v0.8.1'e ertelenir.

4. **Max dosya sayısı 10k çok mu, az mı?** Vergi arşivi kullanıcılarından
   geri bildirim gelene dek 10k. `HEKADROP_MAX_BUNDLE_ENTRIES` env override'ı
   opt-in güç kullanıcılar için.

5. **Disk quota check:** receiver diski doldurmaktan nasıl korunur? Bundle
   size introduction'da belli; `std::fs::available_space` (Linux/macOS `statvfs`,
   Windows `GetDiskFreeSpaceEx`) ile pre-check. MVP dışı, v0.8.1.

6. ~~**Kısmi başarı (bazı dosya SHA mismatch) partial-accept mi, atomic-reject mi?**~~
   **Kapandı: atomic-reject seçildi.** §3.6 tek politika olarak atomic-reject
   tanımlar — bir dosyada SHA mismatch olursa tüm bundle atılır, temp dizini
   silinir. Gerekçeler §3.6'da; "zehirli dosya receiver'da kalır" riski
   ortadan kalkar, state machine basitleşir. Resume (§3.9) bundle'ı yeniden
   denemeye olanak tanıdığı için kullanıcı maliyeti sınırlı.

## 12. Referanslar

- `docs/rfcs/0000-template.md` — şablon.
- `docs/rfcs/0003-chunk-hmac.md` (parallel draft) — capabilities frame kaynağı.
- `docs/rfcs/0004-transfer-resume.md` (parallel draft) — resume entegrasyonu.
- `docs/ROADMAP.md:116,125` — v0.8.0 folder streaming gereksinimi.
- `docs/security/threat-model.md` §7.1, §7.3 — path traversal ve symlink race.
- `src/payload.rs:113-470` — `PayloadAssembler` + `FileSink`.
- `src/connection.rs:922-1065` — `unique_downloads_path`, `sanitize_received_name`.
- `src/sender.rs:905-935` — `build_introduction_multi` fallback reference.
- `proto/wire_format.proto:30-71` — `FileMetadata`.
- NearDrop issue #211 — <https://github.com/grishka/NearDrop/issues/211> (erişim 2026-04-24).
- LocalSend protokol spesifikasyonu v2 — <https://github.com/localsend/protocol> (erişim 2026-04-24).
