# RFC 0003 — Chunk-level HMAC-SHA256

- **Başlatan:** @ebubekir (HekaDrop core team)
- **Durum:** Draft
- **Oluşturulma tarihi:** 2026-04-24
- **Hedef sürüm:** v0.8.0 ("Protokol Sağlamlaştırma", ROADMAP §Q1 v0.8.0)
- **İlgili issue:** #— (henüz açılmadı); deferred risk tablosu `threat-model.md` §8 D-2.
- **İlişkili RFC'ler:** 0004 (resume protokolü) ve 0005 (folder streaming) bu RFC'nin tanımlayacağı `Capabilities` mesajını ve chunk-integrity primitive'ini yeniden kullanacak. Her üç RFC paralel yazılıyor; `Capabilities` tasarımının burada "first mover" olarak konumlanması gerek.

## 1. Özet

HekaDrop'a **chunk başına** HMAC-SHA256 bütünlük etiketi eklenir. Mevcut `SecureCtx` (bkz. `src/secure.rs:78,113`) UKEY2 türevi `send_hmac_key` ile her **frame**'in tamamını zaten Encrypt-then-MAC disiplini altında koruyor — yani **wire transit seviyesinde** tampering hâlihazırda yakalanır ve bu RFC **oraya ek bir savunma katmanı iddia etmez**. Chunk-HMAC'in gerçek gerekçesi farklı bir katmanda yatar:

1. **Resume protokolünün O(1) önkoşulu:** Receiver'ın elindeki partial dosyada hangi byte aralığının "intact" olduğu, sender tarafından full-file SHA-256 yeniden hesaplanmadan doğrulanabilsin (RFC-0004 fast-path bu önkoşula bağlıdır).
2. **Early abort / storage corruption:** Frame-level MAC doğrulandıktan *sonra* plaintext diske yazılıncaya kadar geçen sürede (receiver-side disk bitflip, memory corruption, receiver-internal tampering) oluşabilecek bozulma, bugün ancak transfer sonundaki SHA-256 karşılaştırmasıyla yakalanır; chunk-HMAC bunu her chunk'ta **erken** yakalar.
3. **Partial file integrity as a first-class protocol primitive:** "Elimde chunk 0..k-1 doğrulandı" ifadesi protokolde taşınabilir, görünür, kriptografik olarak pin'lenmiş bir olgudur — ne receiver-local bir best-effort hash, ne de sender'a opak bir claim.

Bu RFC her `PayloadChunk`'ın **düz metin gövdesine** HKDF ile ayrılmış, yeni bir `chunk_hmac_key` altında üretilen 32 bayt HMAC-SHA256 etiketi ekler. Etiket, `PayloadChunk` gönderildikten **hemen sonra** ayrı bir `ChunkIntegrity` shared-frame ile iletilir; alıcı her chunk'ı diske yazmadan önce tag'i doğrular, mismatch'te transfer derhal iptal edilir ve placeholder dosya silinir. Wire-level capabilities negotiation peer her iki taraf da bu özelliği duyurmuşsa aktifleşir; aksi hâlde mevcut "end-of-file SHA-256" davranışı korunur. Upstream Quick Share proto şemasına breaking değişiklik getirilmez.

## 2. Motivasyon

### 2.1 Problem 1 — Resume fast-path için O(1) önkoşul

RFC 0004 transfer resume'i tanımlıyor: alıcı yarım dosyayı `~/.hekadrop/partial/` altında tutacak ve sender'a "ofset X'e kadar sende hangi byte range intact?" önergesi sunacak. Bugünkü tek kriptografik karşılaştırma `FileMetadata.payload_hash` (end-of-file SHA-256) — yani tüm dosya tamamlanmadan hash çıkmaz; partial için doğrulanabilir bir primitif yok. Fallback olarak sender `[0..offset]` aralığını yeniden hash'leyebilir, ama 10 GiB için SHA-NI'siz ~30 saniye CPU işi. Chunk-HMAC ile alıcı "chunk 0..k-1 tag'leri benim nezdimde doğrulandı; lütfen chunk k'dan itibaren gönder" diyebilir; sender aynı `chunk_hmac_key`'i yeniden türettiği için (deterministic HKDF) iddiayı **sadece son chunk tag'ini karşılaştırarak** O(1) doğrular.

Dolayısıyla chunk-HMAC **resume'den önce merge edilmelidir**. Bu RFC, 0004'ün zeminidir.

### 2.2 Problem 2 — Erken tespit ve storage corruption

`SecureCtx` (`src/secure.rs:78,113`) frame-level Encrypt-then-MAC ile **wire transit'teki** tampering'i zaten yakalar; bu RFC oraya bir savunma katmanı iddia etmez. Ancak frame MAC doğrulandıktan sonra plaintext chunk `FileSink::write_chunk` buffer'ından diske flush'lanıncaya kadar geçen sürede bozulma kaynakları vardır:

- **Receiver-side storage path corruption:** RAM bitflip, disk controller bug, ECC olmayan donanım, kötü kablo. Bugünkü tespit yalnızca `last_chunk` sonrası end-of-file SHA-256 ile olur; yani 10 GiB dosyada bozulma **ilk chunk'ta bile olsa** 10 GiB trafik harcanır.
- **Defence in depth — frame MAC regresyonu:** Tarihte constant-time karşılaştırma regresyonları, sequence counter wrap bug'ları, padding oracle'lar görüldü. Chunk-level bağımsız tag, frame-level MAC'in sessiz regresyonunu görünür kılar (fail-loud).
- **Ağ bozulması / sessiz corruption:** TCP checksum 16-bit; Stone & Partridge (SIGCOMM 2000) büyük dosyalarda false-negative'i belgeledi. Frame MAC bunu yakalar; bir bug varsa chunk-HMAC yakalar.

Somut ölçüm: 10 GiB dosya, 100 MiB/s gerçek Wi-Fi throughput → **100 s**. Chunk-HMAC ile ilk bozulan chunk (`CHUNK_SIZE = 512 KiB`) **ilk 0.005 s** içinde tespit edilir (chunk 1). Mevcut tasarımda 100 s kaybedilir ve kullanıcı "SHA-256 mismatch, yeniden dene" mesajı alır.

## 3. Ayrıntılı Tasarım

### 3.1 Wire Format — Seçenek (a) vs. (b)

Quick Share `PayloadTransferFrame.PayloadChunk` proto'suna (bkz. `proto/offline_wire_formats.proto:188-196`) yeni alan ekleyemeyiz çünkü bu upstream Google spec'idir; Android tarafı bilmediği alanı yok sayar ama bu durumda capabilities negotiation'dan söz edemez ve davranış sessizce sessize alınmaz — yalnızca bizim iki uçlu trafiğimiz işe yarar.

**Seçenek (a): Chunk body'sinin son 32 baytı tag.** `effective_body = body[..body.len()-32]`. Geri uyumsuz: eski HekaDrop sürümleri bu 32 baytı payload'ın parçası olarak disk'e yazar → dosya bozulur, SHA-256 mismatch. Feature flag gerektirir ve yine de kullanıcı başka bir Quick Share peer'i ile (Android, rquickshare) konuşurken bu kip kapatılmalı. Protokol katmanlamasını kirletir: `PayloadChunk.body` anlambilimsel olarak "dosya içeriği"dir; integrity metadata'sı orada yaşamamalı.

**Seçenek (b): Ayrı `ChunkIntegrity` shared-frame.** `PayloadChunk` normalde nasılsa öyle gönderilir. Hemen ardından (aynı `SecureCtx::encrypt` zinciri altında, yani mevcut sequence counter disiplinine uyarak) ayrı bir shared-frame tipi — HekaDrop-özel — iletilir. Bu frame Quick Share peer'i tarafından alındığında parse hatası verir mi? **Hayır**: alıcı peer'ın capabilities'i yok ise sender zaten bu frame'i göndermez (bkz. §4). Peer eşit seviyedeki HekaDrop ise frame tanınır.

**Kritik:** Upstream `OfflineFrame.V1Frame.FrameType` enum Google-tanımlıdır ve biz orada **yeni enum varyantı eklemeyiz**. Upstream'deki tanımlı değerler (`proto/offline_wire_formats.proto:47` civarı; 1=ConnectionRequest, 2=ConnectionResponse, 3=PayloadTransfer, 4=KeepAlive, 5=Disconnection, 6=Introduction, 7=`PAIRED_KEY_ENCRYPTION`, 8=`PAIRED_KEY_RESULT`) HekaDrop için dokunulmazdır. Önceki RFC taslaklarında "FrameType = 7" gibi slot iddiaları **yanlıştı**; 7 zaten `PAIRED_KEY_ENCRYPTION` tarafından kullanılıyor.

Çözüm: HekaDrop uzantılarını **hiçbir durumda** upstream `V1Frame.FrameType` enum'una ekleme; bunun yerine kendi `HekaDropFrame` proto wrapper'ımızı `SecureCtx::encrypt` payload'ı olarak gömüp karşı tarafa yolluyoruz. Parser `OfflineFrame` mı yoksa `HekaDropFrame` mı olduğunu **magic prefix** (ilk 4 bayt sabit `0xA5 0xDE 0xB2 0x01`) ile ayırt eder. HekaDrop olmayan peer prefix'i tanımaz → `OfflineFrame::decode` hatası → frame drop; ama bu duruma zaten capabilities-gate sayesinde girilmez.

**Öneri: (b).** Karar gerekçeleri:

1. Upstream wire format'ı breaking yapmıyor.
2. Protokol katmanlama temiz kalıyor: integrity verisi integrity frame'inde.
3. Capabilities-gate üzerinde çalışır → 3rd-party Quick Share peer'leri etkilenmez.
4. 0004 (resume) ve 0005 (folder) aynı shared-frame mekanizmasını kullanabilir.

### 3.2 `HekaDropFrame` wrapper ve `Capabilities` mesajı (first mover — 0004/0005 ortak)

Kanonik şema (üç RFC'nin tümü bu tanımlara referans verir; çelişki olursa bu bölüm normatiftir):

#### Wire layout — magic prefix protobuf'un dışındadır

`HekaDropFrame` discriminator'ı (4-byte sabit `0xA5DEB201`) **protobuf message
içinde değil**, payload'ın ham byte prefix'i olarak akar. Aksi halde protobuf
`fixed32 field=1` wire encoding'i tag-byte (`0x0d`) + little-endian değer
üretirdi; ilk 4 byte'ı sabit bir prefix olarak okuma garantisi olmaz (Gemini
PR-85 review). Magic'i protobuf'tan dışlamak hem dispatcher mantığını
basitleştirir hem de byte sırası belirsizliğini ortadan kaldırır.

Quick Share frame katmanı zaten `[4-byte big-endian length][frame body]`
formatındadır. HekaDrop frame body'sinin yapısı:

```
+------------------+----------------------------+
|  magic (4 byte)  |  HekaDropFrame protobuf    |
|  0xA5 DE B2 01   |  (varint-delimited fields) |
+------------------+----------------------------+
        ▲
        └─── big-endian sabit; protobuf dışı; capabilities-gate
             aktive olmadığında bu prefix asla iletilmez
```

Dispatcher (alıcı tarafta) mantığı:

```rust
// pseudocode — gerçek implementation src/frame.rs içinde
fn dispatch(frame_body: &[u8]) -> Result<Frame, Error> {
    if frame_body.len() >= 4 && &frame_body[..4] == HEKADROP_MAGIC_BE {
        let inner = &frame_body[4..];
        Ok(Frame::HekaDrop(HekaDropFrame::decode(inner)?))
    } else {
        Ok(Frame::Offline(OfflineFrame::decode(frame_body)?))
    }
}

const HEKADROP_MAGIC_BE: &[u8; 4] = &[0xA5, 0xDE, 0xB2, 0x01];
```

Eski Quick Share peer'ı `0xA5DEB201` ile başlayan body'yi varint length veya
field tag olarak parse etmeye çalışır → erken `OfflineFrame::decode` hatası →
drop. Bu zaten capabilities-gate aktif değilken HekaDrop tarafının böyle bir
frame **göndermemesi gerekir**; magic + dispatcher kombinasyonu defensive
backstop'tur.

#### Protobuf şema (magic'siz)

```proto
// proto/hekadrop_extensions.proto (yeni dosya, HekaDrop-özel)
syntax = "proto3";
package hekadrop.ext;

message HekaDropFrame {
  // NOT: Magic discriminator (0xA5DEB201) bu mesaj tipinin ham byte
  // prefix'idir, protobuf field değildir. Wire layout açıklaması §3.2'nin
  // başında. Dispatcher 4 byte'lık prefix'i strip eder ve buradan başlar.
  uint32 version = 1;  // v0.8 = 1; monoton artar
  oneof payload {
    Capabilities    capabilities  = 10;  // bu RFC
    ChunkIntegrity  chunk_tag     = 11;  // bu RFC
    ResumeHint      resume_hint   = 12;  // RFC-0004
    ResumeReject    resume_reject = 13;  // RFC-0004
    FolderManifest  folder_mft    = 14;  // RFC-0005
    // 15..63 — reserved for future v0.x minor additions
  }
}

message Capabilities {
  uint32 version  = 1;  // monoton artan; v0.8.0 için = 1
  uint64 features = 2;  // bitfield (aşağıdaki sabitler)
}

// Feature bitleri — üç RFC de bu sabit numaralara referans verir.
// (Proto sabit değil; dokümantasyon. Rust tarafı `pub const` olarak tutar.)
//   CHUNK_HMAC_V1     = 0x0001   // bit 0, bu RFC
//   RESUME_V1         = 0x0002   // bit 1, RFC-0004
//   FOLDER_STREAM_V1  = 0x0004   // bit 2, RFC-0005
//   0x0008..0x8000    — reserved for v0.8–v1.0

message ChunkIntegrity {
  int64  payload_id  = 1;   // PayloadHeader.id ile eşleşir
  int64  chunk_index = 2;   // 0'dan başlayan monotonik sayaç
  int64  offset      = 3;   // PayloadChunk.offset aynası (redundant integrity)
  uint32 body_len    = 4;   // Ayrı doğrulama: len(body) bu değere eşit olmalı
  bytes  tag         = 5;   // HMAC-SHA256 (32 bayt), ayrıntı §3.4
}
```

**Oneof slot stratejisi:** Slot numaraları **10'dan başlar** — 1..9 arası ileriki sürümlerde (v0.9+) temel (non-payload) alanlar için bilinçli olarak açık bırakılır. 10–14 bu RFC paketinde sabitlenmiş beş slot'tur; 15..63 minor eklemeler için rezerve. Önemli: proto3'te `oneof` içinde `reserved` numara aralığı **yasaklama anlamına gelir ve oneof'un ileride genişlemesini engeller**, dolayısıyla burada `reserved` bloğu **kullanılmaz**; bunun yerine kullanılmayan slot numaraları sadece terkedilmiş olarak bırakılır ve yukarıdaki policy tablosu ile dokümante edilir.

### 3.3 Capabilities Negotiation Akışı

```
ConnectionRequest → UKEY2 handshake → ConnectionResponse(ACCEPT)
    → PairedKeyEncryption (mevcut)
    → Capabilities (YENI — SecureCtx altında, her iki taraf gönderir)
    → payload akışı
```

Ekleme noktası: `connection.rs` Introduction öncesi. PairedKeyEncryption phase'i tamamlanır tamamlanmaz her iki uç kendi `Capabilities`'ini yollar (sender → receiver ve receiver → sender). Karşı taraftan 2 sn içinde `Capabilities` almazsa: **legacy mode** (peer HekaDrop değil veya <v0.8.0). Legacy mode'da `chunk_hmac_key` asla türetilmez, `ChunkIntegrity` frame'i gönderilmez, alıcı da beklenmez.

Timeout neden 2 sn? PairedKeyEncryption ile Introduction arası mevcut akışta genellikle <100 ms; 2 sn cömert bir margin, handshake `HANDSHAKE_READ_TIMEOUT = 30 s` limitinin çok altında. `Capabilities` zorunlu değil — legacy Quick Share peer'ı asla göndermez; o akışta receiver `Capabilities` beklemek yerine Introduction frame'ini ilk gördüğünde "peer capabilities bildirmemiş = 0" varsayar.

Negotiated `active_caps = my_caps & peer_caps`. Bit-AND seçimi: bir taraf bir özelliği kapatmışsa (örn. CLI flag `HEKADROP_DISABLE_CHUNK_HMAC_V1=1`) ikili AND ile sessizce devre-dışı.

### 3.4 HMAC Anahtar Türetmesi

**Ayrı HKDF dalı** kullanılır. Gerekçe: domain separation — `send_hmac_key` frame-level authenticate için kullanılmaktadır; aynı anahtarı chunk-level MAC için yeniden kullanmak cross-protocol confusion saldırı yüzeyi açar (teorik; uygulamada HMAC-SHA256 multi-use'a dayanıklı olsa da NIST SP 800-108 ve RFC 5869 §3.1 ayrı kullanım-etiketleri önerir).

```
IKM  = next_secret          # mevcut UKEY2 türevi, src/crypto.rs Level-2 (§6.3 threat-model)
salt = empty                # zero-length salt; domain separation `info` etiketinden geliyor
info = b"hekadrop chunk-hmac v1"
chunk_hmac_key = HKDF-SHA256(IKM, salt, info, 32)
```

> **Salt seçimi notu (PR #102 Copilot review reconciliation):** Önceki taslak
> `salt = sha256("hekadrop:chunk-hmac:v1")` öneriyordu, ancak wire-byte
> spec (`docs/protocol/chunk-hmac.md` §4) ve referans implementasyon
> (`hekadrop-core::chunk_hmac::derive_chunk_hmac_key`) **empty salt + `info`
> etiketi** ile domain separation sağlıyor. RFC ve spec birlikte tek
> derivasyona kilitli; KAT'lar bu derivasyon ile üretilir. v1.x cycle'ında
> derivasyon değişirse `chunk_hmac_v2` capability bit'i ile yeni RFC
> revizyonu açılır.

Her iki yön için **aynı** `chunk_hmac_key` kullanılır (dosya transferi tek yönlüdür; ama simetri korunur). `next_secret` halihazırda `DerivedKeys` içinde yaşıyor (bkz. threat-model §6.3 Level-1); yeni bir UKEY2 round-trip gerekmez.

### 3.5 Tag Hesaplama

```
message = payload_id (8 bayt big-endian)
        || chunk_index (8 bayt big-endian)
        || offset (8 bayt big-endian)
        || body_len (4 bayt big-endian)
        || body (raw plaintext chunk)

tag = HMAC-SHA256(chunk_hmac_key, message)
```

**Neden offset + chunk_index ikisi de?** Redundancy; saldırgan reordering yapmaya kalkarsa her iki alan da hash altında, dolayısıyla tag doğrulama yer-değiştirmeyi yakalar. `body_len` de hash altına alınır — length-extension ya da pre-image confusion korunur (HMAC zaten length-extension immune'dur ama açık netlik iyi dokümantasyon).

**Neden plaintext body?** Frame-level HMAC'ten çıkan plaintext'i chunk-level MAC altında da authenticate ediyoruz — "defense in depth". Ciphertext üstünden MAC (MtE-like) CBC + HMAC'in zaten verdiği şeyi tekrarlar ve padding oracle yüzeyini genişletebilir.

### 3.6 Tag Doğrulama (Alıcı)

`PayloadAssembler::ingest` (`src/payload.rs:233-264`) şu adımlarla genişler:

1. `PayloadChunk` alınır. Eğer `active_caps & CHUNK_HMAC_V1 == 0` → mevcut akış (değişiklik yok).
2. Eğer `CHUNK_HMAC_V1` aktif: `PayloadChunk` işleme **almadan** aynı `SecureCtx` stream'inde bir sonraki frame'i oku, `HekaDropFrame.ChunkIntegrity` ile eşleşmesi beklenir.
3. Sıra uyumu kontrolleri:
   - `ChunkIntegrity.payload_id == PayloadHeader.id`
   - `ChunkIntegrity.chunk_index == expected_next_index[payload_id]` (monotonik artan, `expected_next_index` `PayloadAssembler` state'ine eklenir)
   - `ChunkIntegrity.offset == PayloadChunk.offset`
   - `ChunkIntegrity.body_len == body.len()`
4. **Tag uzunluk kontrolü (`ChunkIntegrity.tag.len() == 32`)** — constant-time karşılaştırmadan **önce** yapılır. Yanlış uzunlukta tag ya da eksik alan → `HekaError::ChunkHmacMismatch`, transfer abort. Non-constant length check burada timing yüzeyi açmaz çünkü `tag` attacker-controlled bir payload'dır ve uzunluğu zaten attacker tarafından biliniyor; gizli değildir.
5. `expected_tag = HMAC-SHA256(chunk_hmac_key, message)` hesapla (§3.5 formatı).
6. `subtle::ConstantTimeEq::ct_eq(&expected_tag, &ChunkIntegrity.tag)` — **constant-time** karşılaştırma (mevcut kullanım `src/crypto.rs:82`). Mismatch → `HekaError::ChunkHmacMismatch { payload_id, chunk_index }`, transfer abort, placeholder dosya silinir (`remove_partial_file` helper — `src/payload.rs:480+` civarındaki mevcut cleanup yolu üzerinden).
7. `expected_next_index[payload_id] += 1`, chunk body `sink.writer.write_all`'a devam eder.

Hata yolu kritik: tag mismatch'te **partial_file disk'ten mutlaka silinmelidir**, çünkü resume protokolü (RFC 0004) bozuk chunk içeren partial'i geçerli sayarsa attacker-controlled corruption kalıcı olur. Silme başarısızsa log'a `error!` seviyesinde uyarı + dosya `.corrupt` uzantısıyla rename.

### 3.7 Gönderim Sırası

```
for chunk in file.chunks(CHUNK_SIZE):
    payload_transfer = wrap_payload_transfer(..., body=chunk, flags=last?)
    enc1 = ctx.encrypt(payload_transfer.encode())
    write_frame(socket, enc1)

    integrity = HekaDropFrame { ChunkIntegrity { payload_id, chunk_index, ..., tag } }
    enc2 = ctx.encrypt(integrity.encode())
    write_frame(socket, enc2)
```

İki ayrı `SecureCtx::encrypt` çağrısı → iki ayrı sequence number. Bu sender'ı `client_seq` tarafında 2× hızlı tüketir; mevcut overflow guard `checked_add` 2^31 mesajla yeterli (2^30 chunk × 512 KiB ≈ **512 TiB**, nasıl olsa erişilmez).

**Alternatif:** Tek frame içinde `HekaDropFrame` ile `PayloadTransferFrame`'i concatenate et. Reddedildi: wire format'ta frame = 4-byte length prefix + protobuf; her seferinde bir mesaj. Composite frame için yeni parser gerekir.

### 3.8 Efor Kırılımı

| İş | Saat | 0004 ile Kesişim |
|---|---|---|
| `proto/hekadrop_extensions.proto` + build.rs integration | 2 | ✓ (ortak dosya; 0004 reserved slot açar) |
| `Capabilities` negotiation (`src/capabilities.rs` yeni modül) | 4 | ✓ (0004/0005 aynı modülü genişletir) |
| `HekaDropFrame` magic-prefix dispatcher (`src/frame.rs` ext) | 3 | ✓ |
| `chunk_hmac_key` HKDF türetme + `DerivedKeys` genişletme | 2 | — |
| Sender yolunda `ChunkIntegrity` üretimi (`src/sender.rs`) | 3 | — |
| Receiver yolunda tag doğrulama (`src/payload.rs`) | 4 | ○ (0004 partial resume logic aynı yeri değiştirir; merge çakışması beklenir) |
| Unit + property test'ler | 4 | — |
| Integration test (1 GiB + corruption injection) | 3 | — |
| Fuzz harness (`fuzz_chunk_hmac_verify`) | 2 | — |
| Benchmark (`benches/chunk_hmac.rs`, Criterion) | 2 | — |
| Dokümantasyon (`docs/protocol/chunk-hmac.md`) | 2 | ✓ (0004 aynı dizine yazar) |
| **Toplam** | **31** | — |

Paralel çalışılırsa 0004 ile ortak primitifler (`proto/hekadrop_extensions.proto`, `src/capabilities.rs`) iki RFC arasında tek kez yazılır; 0003 onları tanımlayan RFC'dir.

## 4. Alternatifler

### 4.1 AES-GCM'e Geçiş

**Reddedildi (bu RFC kapsamında).** AES-GCM per-record AEAD sağlardı, ama:
- Upstream Quick Share spec'i AES-CBC + HMAC'tir; Android peer'ları AES-GCM'yi anlamaz.
- Migration breaking; feature-flag'li çift-katlı implementasyon gerekir.
- Ayrı bir RFC konusu (ileride).

### 4.2 Salt SHA-256 chunk hash (MAC'siz)

**Reddedildi.** MAC anahtarı yoksa tampering yakalanmaz; saldırgan hem body hem hash'i tamperler. Mid-stream corruption için gürültü-bazlı senaryoda işe yararlar (§2.1 ikinci madde), ama resume protokolünde receiver'ın iddiasını sender doğrulayamadığından 0004'e zemin olmaz.

### 4.3 BLAKE3 / Poly1305

**Reddedildi.** BLAKE3 daha hızlı (benchmark: ~3× SHA-256) ama yeni crypto primitif → audit yüzeyi büyür. SHA-256 zaten `sha2` crate üzerinden hot path'teki hasher (`src/payload.rs:378`). HMAC-SHA256 ek kod yolu yok, yalnızca yeni key. Poly1305 one-time MAC; key re-use catastrophic — nonce yönetimi zorlaşır. HMAC-SHA256 key-reuse safe.

### 4.4 Seçenek (a) — Chunk body suffix

§3.1'de detaylı tartışıldı. Reddedildi: protokol katmanlama ihlali + interop kırılımı.

## 5. Geriye Uyumluluk / Migration

- **Wire format:** Quick Share proto'larına değişiklik yok. Yeni proto: `proto/hekadrop_extensions.proto` (bizim yönetimimizde).
- **Peer interop:** `Capabilities` yoksa legacy mode; tam geri uyumlu. Android / rquickshare / NearDrop peer'ları etkilenmez.
- **Config:** `HEKADROP_DISABLE_CHUNK_HMAC_V1=1` env var ile sender-side opt-out (debug / A/B için). Receiver zaten peer capabilities'i bildirmemişse legacy.
- **Feature flag gerekir mi?** Hayır — capabilities-gate zaten flag görevi görür. Ama release sonrası ilk iki hafta telemetry (diag panel) için `stats.json` içine `chunk_hmac_used: bool` field'ı eklenir.

## 6. Güvenlik Değerlendirmesi

### 6.1 Threat Model Etkisi

Mevcut `threat-model.md` §5.3 "Transfer" STRIDE tablosunda etkilenen hücreler:

- **T (Tampering) — wire transit (A2: ciphertext bit-flip):** Frame-level HMAC bunu **zaten yakalar** (`SecureCtx::decrypt_verify`); chunk-HMAC buraya yeni bir kilit eklemez. Chunk-HMAC'in katkısı **defence-in-depth** perspektifinden: frame-level MAC'in bir regresyonu (örn. `subtle::ConstantTimeEq` mis-invocation, sequence counter wrap bug'ları, padding oracle) durumunda chunk-level bağımsız tag bu regresyonu fail-loud hale getirir. Yani chunk-HMAC "wire transit koruması" iddia etmez ama frame-MAC sessiz bir şekilde devre dışı kalırsa yüzeye çıkarır.
- **T — Mid-stream silent corruption:** Bugün "end-of-file SHA-256" ile yakalanır ama geç; chunk-HMAC ile her chunk'ta yakalanır. Threat model'e yeni satır eklenecek: "Chunk-level tag (§3.5); mismatch → immediate abort + partial cleanup."
- **I (Information disclosure):** Tag plaintext gönderilir ama HMAC one-way → IKM (`chunk_hmac_key`) sızdırmaz. Timing oracle: constant-time verify (§3.6/5). Payload hacmi anlamına gelebilecek length-leak zaten `PayloadChunk.body` boyutundan var; `ChunkIntegrity.body_len` yeni bilgi eklemez.
- **D (Denial of service):** Saldırgan (malicious peer, A3) her chunk'ta tag mismatch üretirse → transfer erken iptal → işini **kolaylaştırır** (eski akışta da kullanıcı-controlled cancel). Yeni DoS vektörü yok. Kapasite tüketimi: her chunk için +32 bayt + proto overhead + 1 ek sequence — ihmal edilebilir.
- **E (Elevation):** Yeni kod yolu `PayloadAssembler`'da proto decode + HMAC verify; her ikisi de safe Rust + constant-time. Yeni `unsafe` yok.

### 6.2 Nonce/IV Analizi

- `ChunkIntegrity` şifreli `SecureCtx` stream'inde taşınır → kendi IV'si var (mevcut frame-level CBC).
- Tag-content IV kullanımı yok; HMAC deterministic.
- Replay: saldırgan eski bir (chunk_index, tag) çiftini replay ederse? `expected_next_index` monotonik → eski index'e dönüş `HekaError::ChunkHmacMismatch` (index mismatch) ile reddedilir.
- Cross-session replay: `chunk_hmac_key` her oturumda farklı (HKDF `next_secret` ephemeral) → cross-session tag reuse imkansız.

### 6.3 Domain Separation

HKDF info string: `"hekadrop chunk-hmac v1"`. Gelecek sürümlerde `v2` gerekirse ayrı anahtar; saldırgan v1 tag'ini v2 context'inde replay edemez.

### 6.4 Timing Side-Channel

`subtle::ConstantTimeEq::ct_eq` (`src/crypto.rs:10,82`) zaten kullanılıyor. Yeni verify aynı API'yi kullanır. Early-return `body_len` mismatch'ten once yapılabilir (sabit "invalid length" branch); length kendi başına plaintext'tir, zaten açık → length-bazlı timing leak yok.

### 6.5 Audit Checklist (Trail of Bits / Cure53)

- [ ] HKDF info string `"hekadrop chunk-hmac v1"` RFC 5869 domain separation için yeterli mi?
- [ ] `next_secret`'in iki farklı HKDF dalına beslenmesi (mevcut L2 + yeni chunk-hmac) ikili Level-2 türev olarak kabul edilir mi?
- [ ] `ChunkIntegrity` frame'inin replay koruması `expected_next_index` ile yeterli; monotonic counter overflow `i64` → pratik değil.
- [ ] Partial file cleanup'ın fail'i `.corrupt` rename ile resume protokolünü yanıltmaz mı? (0004'te eşgüdüm.)

## 7. Performans Değerlendirmesi

### 7.1 Bandwidth Overhead

- `ChunkIntegrity` proto serialized ≈ 60 bayt (tag 32 + payload_id + chunk_index + offset + body_len + overhead).
- `CHUNK_SIZE = 512 * 1024 = 524 288 bayt`.
- Overhead: `60 / 524288 ≈ 0.011%`. Ayrıca frame header (4-byte length prefix) ve `SecureCtx` HMAC + IV padding ≈ 60 bayt ek → toplam ~120 bayt / 512 KiB = **~0.023%**.

### 7.2 CPU Overhead

- HMAC-SHA256 hesaplaması 512 KiB için ~0.5 ms modern x86 (AES-NI yok, SHA-NI var/yok'a göre). Mevcut dosya-geneli SHA-256 hasher zaten aynı 512 KiB'i işliyor (`src/payload.rs:409`); chunk-HMAC bunu ~2× yapar (hash + HMAC).
- Tahmini throughput regresyon: **%3-5** tek çekirdek, CPU-bound senaryoda. Ağ-bound senaryoda (Wi-Fi ~100 MiB/s): görünmez.

### 7.3 Benchmark Planı

`benches/chunk_hmac.rs` — Criterion. Ölçümler:

1. `bench_chunk_hmac_sign` — tek 512 KiB chunk için tag üretim süresi.
2. `bench_chunk_hmac_verify` — tek chunk verify.
3. `bench_pipeline_1gib` — 1 GiB virtual file pipeline (in-memory, disk I/O hariç); legacy vs chunk-HMAC aktif throughput karşılaştırması.

Regression gate: CI'da %10'dan fazla throughput düşüşü → PR red.

## 8. Test Planı

### 8.1 Unit

- `crypto::chunk_hmac_sign_verify_roundtrip` — rastgele key + chunk, sign → verify true.
- `crypto::chunk_hmac_verify_fails_on_body_tamper` — bir byte flip → verify false.
- `crypto::chunk_hmac_verify_fails_on_index_tamper` — chunk_index 0 → 1, verify false.
- `capabilities::negotiation_and_off_by_peer_absence` — legacy peer timeout → `active_caps == 0`.

### 8.2 Property (proptest)

```rust
proptest! {
    #[test]
    fn chunk_tag_any_body_flip_detected(body in any::<Vec<u8>>(), flip_at in 0usize..65536) {
        let k = [7u8; 32];
        let tag = chunk_hmac_sign(&k, 0, 0, 0, &body);
        if body.is_empty() { return Ok(()); }
        let mut bad = body.clone();
        bad[flip_at % bad.len()] ^= 0x01;
        prop_assert!(!chunk_hmac_verify(&k, 0, 0, 0, &bad, &tag));
    }
}
```

### 8.3 Integration

- `tests/chunk_hmac_1gib_flip.rs` — 1 GiB random file; sender karşı 5. chunk'ın orta byte'ını flip eder (test harness'taki bir "man-in-the-pipe" adapter üzerinden). Beklenti: alıcı chunk 5 ingest'inde `ChunkHmacMismatch` hatası, placeholder dosya `~/Downloads/` altından silinmiş, `stats.json`'a abort kaydedilmiş.
- `tests/chunk_hmac_legacy_peer_fallback.rs` — capabilities bildirmeyen fake peer; alıcı `ChunkIntegrity` beklemez, mevcut end-of-file SHA-256 akışı.

### 8.4 Fuzz

Yeni harness: `fuzz/fuzz_targets/fuzz_chunk_hmac_verify.rs`. Girdi: `(key_seed, payload_id, chunk_index, offset, body_len, body_bytes, tag_bytes)` — crash-free + no UB. Corpus seed'leri: 1024 rastgele valid + 1024 mutated.

## 9. Dokümantasyon Etkisi

- `README.md` §Protokol: yeni özellik "per-chunk HMAC-SHA256 integrity (v0.8.0+, peer capabilities gated)" satırı.
- `docs/protocol/chunk-hmac.md` — wire format, key schedule, test vector KAT.
- `docs/security/threat-model.md` §5.3 tabloda "Chunk-level tag" satırı eklenir; §8 D-2 "accepted deferred" → "resolved in v0.8.0 via RFC-0003".
- `CHANGELOG.md` — v0.8.0 bölümü altında "Protocol: chunk-level HMAC-SHA256 (opt-in via capabilities; peer negotiated)".

## 10. Açık Sorular

1. **`Capabilities.features` kaç bit reserve edilmeli?** `uint64` 64 bit; RFC 0003-0005 üçü dolu, kalan 61 bit. Gelecek 2 yıl için bol; ancak geçmiş deneyimle (IPv4 flag field'ları) daha çok bit alanı iyi fikir. **Öneri:** gerekirse `v2` `Capabilities` mesajı `repeated uint64 features` veya ayrı `extensions map<string, bytes>` ile açılır; `Capabilities.version` alanı zaten bu upgrade'i discoverable kılar. Şimdilik `uint64` yeterli.
2. **Magic prefix `0xA5DEB201` — çakışma riski?** Quick Share `OfflineFrame.version = 1` tipik olarak `0x08 0x01` varint ile başlar. `0xA5` MSB-set varint → prost decode hatası verir. Düşük çakışma riski. Yine de prefix'i `proto/hekadrop_extensions.proto` dokümanında kalıcı olarak sabitlemek gerekli.
3. **`extra_capabilities` bitmap mi `Capabilities` mi?** Quick Share `ConnectionRequestFrame`'de `extra_capabilities` adında bir alan yok (bkz. `proto/offline_wire_formats.proto:71-125` — biz full frame'i kontrol ettik). Dolayısıyla bitmap piggyback seçeneği yok; **ayrı `Capabilities` zorunlu**. ROADMAP §Q1 risk tablosunun "Quick Share extra_capabilities çakışma" maddesi bu RFC ile moot oluyor.
4. **Partial file resume interop:** Eğer v0.8.0 alıcısı v0.8.0 göndericisinden 50% aldı, tag mismatch'te partial silindi — sonra aynı peer yeniden bağlandığında chunk 0'dan mı başlar? Evet; RFC 0004 bu yeniden-başlangıcı `partial_hash` ile optimize eder. 0004 merge'ünden önce chunk-HMAC yalnız erken-tespiti sağlar, resume sağlamaz.
5. **`HEKADROP_DISABLE_CHUNK_HMAC_V1=1` env var gerçekten gerek mi?** A/B metrik ve emergency rollback için faydalı; ama çoğu kullanıcı görmez. `off-by-default via capabilities AND` davranışıyla gereksiz olabilir. Reviewer'a bırakılmış.

## 11. Referanslar

- RFC 2104 — HMAC. <https://datatracker.ietf.org/doc/html/rfc2104>
- RFC 5869 — HKDF. <https://datatracker.ietf.org/doc/html/rfc5869>
- NIST SP 800-108 — KDF in counter/feedback mode, domain separation guidance.
- Stone, J. & Partridge, C. — "When the CRC and TCP Checksum Disagree", SIGCOMM 2000.
- Google Quick Share protokol proto'ları: `proto/offline_wire_formats.proto`, `proto/wire_format.proto`.
- HekaDrop internal: `docs/security/threat-model.md` §5.3 (transfer STRIDE), §6.3 (HKDF tablosu), §8 D-2 (deferred risk).
- İlişkili RFC'ler: 0004 (resume — taslak), 0005 (folder streaming — taslak); her ikisi de bu RFC'deki `Capabilities` ve `HekaDropFrame` mekanizmasını yeniden kullanacak.
- Marlinspike, M. — "The Cryptographic Doom Principle" (EtM-before-decrypt disiplinine referans; bu RFC aynı disiplini chunk seviyesinde korur).
