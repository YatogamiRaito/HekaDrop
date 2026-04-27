# RFC 0002 — URL Payload

- **Durum:** Önerilen (v0.7.0 için)
- **Tarih:** 2026-04-24
- **Karar:** A (Uygula — ama minimal, "sender auto-tag" scope'uyla)
- **Etkilenen dosyalar:** `src/sender.rs`, (opsiyonel) `src/ui.rs`, yeni testler
- **Tahmini efor:** 3–5 saat
- **İlgili:** `proto/wire_format.proto` (TextMetadata.Type::URL), `src/connection.rs::handle_text_payload`

---

## 1. Özet

URL payload'ı HekaDrop'ta **zaten yarı yarıya çalışan** bir özelliktir: alıcı
tarafta `TextType::Url` gelen metinleri şema allow-list'inden geçirip varsayılan
tarayıcıda açıyor, güvensiz şemaları panoya düşürüyor; proto ağacı tam, testler
mevcut, README iddiası (alıcı tarafı için) kod ile örtüşüyor. Kayıp parça gönderen
tarafta: `send_text()` hangi string verilirse verilsin Introduction'ı
`TextKind::Text` olarak etiketliyor — kullanıcı `https://…` paste'lese bile peer
bunu URL olarak görmüyor. Bu RFC, **küçük cerrahi bir değişiklikle** (sender'da
URL auto-detection + doğru `TextKind::Url` etiketi) URL payload'ı first-class
hâle getirmeyi önerir. Browser-açma akışı halihazırda koda gömülü; yeni UI/CLI
yüzeyi inşa etmeye gerek yok, mevcut "Ctrl+V Quick Share" yolu kendi kendine
zenginleşir. CLI subcommand (`hekadrop send --url`) bu RFC kapsamında **değil**:
HekaDrop bugün clap'siz bir tray app; yeni CLI yüzeyi açmak v0.8+ kapsamına
ertelenir.

## 2. Mevcut Durum — Kod ile Doğrulanmış Kanıtlar

### 2.1 README (PR #80 sonrası)

`README.md` satır 40–41:

> **Çift yönlü**: hem alıcı hem gönderici. Dosya ve metin (URL'ler metin olarak
> gönderilir; alıcı tarafta URL şeması doğrulanırsa otomatik açılır).

Satır 323 (English summary):

> … files and text; URLs ride on the TEXT type and are auto-opened after
> scheme validation …

İddianın iki tarafı var: **(a)** sender URL'i metin olarak yollar, **(b)** alıcı
şema doğrulaması yapıp açar. (b) tamamen gerçek; (a) zayıf yarısıyla gerçek —
sender metin yolluyor ama `URL` tipi işaretlemesini yapmıyor, bu nedenle peer
(Android dahil) URL-otomatik-aç akışına girmiyor.

### 2.2 Alıcı tarafı — tamamen mevcut

`src/connection.rs::handle_text_payload` (satır 827–882):

```rust
TextType::Url => {
    if is_safe_url_scheme(&text) {
        crate::platform::open_url(&text);
        info!("[{}] URL açıldı: {}", peer, log_redact::url_scheme_host(&text));
        ui::notify(..., &i18n::tf("notify.url_opened", ...));
    } else {
        warn!("[{}] güvensiz şemalı URL reddedildi …", peer, ...);
        crate::platform::copy_to_clipboard(&text);
        ui::notify(..., &i18n::tf("notify.text_clipboard", ...));
    }
}
```

`is_safe_url_scheme` (satır 1075–1081): yalnız `http://` / `https://`.
`javascript:`, `file://`, `smb://`, `data:`, `vbscript:`, custom protocol
handler'lar (`zoom-us:`, `ms-msdt:` vb.) reddedilir. 10+ test case mevcut
(satır 1582–1632). PRIVACY log redact'i url_scheme_host ile uygulanmış.

### 2.3 Gönderen tarafı — eksik yarı

`src/sender.rs::send_text` (satır 393–411):

```rust
pub async fn send_text(req: SendTextRequest) -> Result<()> {
    …
    // TEXT (1) — URL tipini peer URL schema doğrulayıp otomatik açar; genel
    // metin için TEXT güvenli default. URL şeklinde ise gene TEXT olarak
    // gönderilir, Android zaten URL-otomatik-aç tarafı için URL meta şart.
    let text_kind = TextKind::Text as i32;
    …
}
```

Yorum içi "URL-otomatik-aç tarafı için URL meta şart" ifadesi kodun kendi
boşluğunu işaretliyor: mevcut kod URL metasını hiç gönderemiyor. Android alıcı
`TextType::Text` gelince share sheet'i pano/Android paylaşıma düşürür; URL
otomatik-aç tetiklenmez.

### 2.4 Proto — tam destek

`proto/wire_format.proto` satır 74–104: `TextMetadata.Type` enum'u `UNKNOWN,
TEXT, URL, ADDRESS, PHONE_NUMBER` değerlerinin tümünü tanımlıyor. `sender.rs`
zaten `text_metadata::Type as TextKind` import ediyor (satır 33); `TextKind::Url
as i32` tek satırlık mesafede.

### 2.5 UI akışı — zaten yerinde

`src/ui.rs`:
- `send_text::` IPC komutu (satır 601) — webview composer'dan metin alır.
- `paste_send` komutu (satır 639) — Ctrl+V sonrası pano içeriğini göndermeye
  tetikler.
- i18n key'leri: `webview.text.placeholder`, `webview.text.send`,
  `notify.url_opened`, `notify.text_clipboard` hepsi mevcut.

### 2.6 CLI — yok

`src/main.rs` clap veya başka argparse kullanmıyor; `env::args` yalnız env var
okuyor (`HEKADROP_NO_UPDATE_CHECK`). `Cargo.toml` clap bağımlılığı içermiyor,
`src/bin/` dizini yok. HekaDrop bugün pure tray/GUI uygulaması.

### 2.7 `src/payload.rs` — enum değil, reassembler

Önceki self-audit notu "`Payload::Url` variant eklenmeli"den bahsediyordu; ama
`src/payload.rs` bir enum tanımı barındırmaz — `PayloadAssembler` (chunk
reassembly, GC, disk streaming) içerir. Wire format'ta tür ayrımı
`TextMetadata.Type` ile yapılır, Rust enum ekleme ihtiyacı yoktur.

### 2.8 Git geçmişi

```
4194f05 security: path traversal + URL scheme allow-list (v0.5.0 critical fixes)
ea920a8 refactor(connection): modular connection/ dir + Dalga 2-3 UX/error/Bytes changes
b298e3c refactor(core): domain error enum + zero-copy Bytes hot-path + UX overhaul
```

v0.5.0'da URL allow-list eklenmiş (alıcı tarafı), sonraki refactor'lar kodu
modüler hâle getirmiş. Sender tarafı hiç dokunulmamış — yorumdaki TODO öylece
kalmış.

## 3. Protokol Araştırması — Quick Share URL Nasıl Yollar?

Google Quick Share (ve Android Nearby Share) tarafında URL wire yerleşimi:

1. **Introduction frame** (sharing_enums tipi `INTRODUCTION`): bir ya da daha
   çok `TextMetadata` içerir. URL için `type = URL (2)`, `text_title = URL'in
   kendisi veya kısa preview`, `payload_id` ve `size` set edilir. URL'in tam
   stringi bu metadata içinde değil, ayrı BYTES payload'ında gelir.
2. **Bytes payload**: `PayloadType::Bytes`, body = UTF-8 URL string'i. Genelde
   tek chunk, `last_chunk=true` flag'iyle. Limiti 4 KiB pratiği yeterli (mevcut
   kodda 4 MiB assembler limiti zaten var).
3. Alıcı Introduction'ı okuyup `(payload_id → TextType::Url)` planlamasını
   yapar, bytes tamamlanınca planlama ile eşleyip URL handler'a router'lar.
   HekaDrop'ta `connection.rs` satır 607–612 ve 836 tam olarak bunu yapıyor.
4. `text/uri-list` MIME string'i **kullanılmaz** — Quick Share protocol'ü kendi
   TextMetadata enum'u ile yönlendirir; MIME doğrudan wire'da yok. Bu wire-level
   URL ayrımı, clipboard API'lerinin `text/uri-list`'i ile karışmamalı.

Özetle: **mevcut altyapımız URL gönderimi için tamamen hazır** — tek gereken
Introduction'da `text_kind` bitini `Url`'e bağlamak.

## 4. Karar — A (Uygula, minimal scope)

### 4.1 Gerekçe

| Soru | Cevap |
|---|---|
| Efor? | 3–5 saat (tek satırlık protocol switch + URL detection + 3 test) |
| Risk? | Çok düşük — alıcı tarafı zaten canlı ve tested, protocol değişmiyor |
| Foundation Q1 dağıtımı? | Hayır — yeni modül/yüzey açmıyor |
| README dürüstlüğü? | A seçeneği hem iddiayı hem kodu aynı seviyeye çıkarır |
| rquickshare'den farklılaşma? | rquickshare URL'i clipboard'a düşürüyor; biz allow-list + `xdg-open` ile tarayıcıda açıyoruz. A bu diferansiyasyonu **iki yönlü** yapar (gönderdiğimiz URL de peer'de düzgün açılır) |

B seçeneği (ertele + README'den çıkar) artık haklı değil: alıcı tarafı zaten
hem kodda hem testlerde mevcut; "çıkarılacak" bir şey yok. README'yi küçültmek
gerçekten mevcut davranışı gizlemek olur. Eksik olan tek bit sender tag'i.

### 4.2 Scope — NE VAR, NE YOK

**Yapılacak:**
- `send_text()` içinde basit URL tespit (string `http://` / `https://` ile
  başlıyor mu) + uygunsa `TextKind::Url` etiketleme.
- `text_title` alanına URL'in kendisini (veya ilk 128 karakteri) yaz.
- 3 yeni birim testi.

**Yapılmayacak (açıkça dışarda bırakıldı):**
- CLI subcommand (`hekadrop send --url …`) — HekaDrop bugün clap'siz tray app;
  CLI yüzeyi açmak başlı başına bir RFC (v0.8+).
- `Payload::Url` Rust enum variant'ı — wire format Rust enum ayrımı istemiyor,
  sadece TextMetadata.Type bit'ini kullanıyoruz. YAGNI.
- Receive-side davranış değişikliği — mevcut open/clipboard akışı yeterli,
  "Copy + Open" action'lı rich notification v0.8+ UX RFC'sinde.
- URL title fetch (HTML `<title>` scrape) — network-reaching logic + privacy
  riski; açıkça ertelendi.
- ADDRESS / PHONE_NUMBER tipleri — aynı path ile ileride eklenebilir; bu
  RFC'de URL'e odaklı kal.

### 4.3 Tasarım — Sender Auto-Tag

#### 4.3.1 URL detection helper (`src/sender.rs`)

```rust
/// Metnin URL payload'ı olarak gönderilip gönderilmeyeceğine karar verir.
///
/// Kriter: trim'lenmiş string **http://** veya **https://** ile başlıyor
/// (case-insensitive). Peer tarafında `is_safe_url_scheme` ile aynı
/// allow-list kullanılır — wire simetrisi kasıtlı: gönderdiğimiz URL'i
/// alıcı da açacak, göndermediklerimizi (javascript: vb.) alıcı da reddedecek.
fn detect_url_kind(text: &str) -> TextKind {
    let t = text.trim_start();
    let starts = |p: &str| t.len() >= p.len() && t[..p.len()].eq_ignore_ascii_case(p);
    if starts("http://") || starts("https://") {
        TextKind::Url
    } else {
        TextKind::Text
    }
}
```

#### 4.3.2 `send_text()` değişikliği

```rust
// ÖNCE
let text_kind = TextKind::Text as i32;

// SONRA
let text_kind = detect_url_kind(&text) as i32;
```

#### 4.3.3 `build_introduction_text()` — `text_title`

URL gönderiminde `text_title` Android share sheet'inde preview olarak görünür.
Mevcut kod `i18n::t("sender.text_summary")` generik string'i koyuyor. URL
ise **preview(url, 128)** yaz (privacy: URL'in tamamı zaten wire'da geliyor,
title ayrıca PII göstermiyor).

```rust
let title = if text_kind == TextKind::Url as i32 {
    preview(text, 128)
} else {
    crate::i18n::t("sender.text_summary").to_string()
};
```

(`preview` helper zaten `connection.rs` içinde; `sender.rs`'e re-export veya
bağımsız kopya — yorum: mevcut preview çok küçük, kopyalama maliyeti iki
satır.)

#### 4.3.4 UI etkisi

Hiçbir UI değişikliği gerekmez. Kullanıcı:
1. Ctrl+V ile URL paste'lerse → `paste_send` → `send_text` → otomatik
   `TextKind::Url` tag.
2. Composer'a URL yazar + Gönder'e basarsa → `send_text::` IPC → aynı yol.

İleride (bu RFC dışında) UI composer'a "URL tespit edildi" görsel ipucu
eklenebilir — zorunlu değil.

### 4.4 Protokol güvenliği notu

Allow-list'i sender'da da tekrarlıyoruz: `http(s)://` dışındaki şemalar
otomatik olarak `TextKind::Text` olur. Böylece saldırgan (veya düşünmeyen
kullanıcı) `javascript:alert(1)` paste'lese bile Introduction'da URL olarak
işaretlenmez; peer zaten `is_safe_url_scheme` ile iki kez süzer. "Defense in
depth": iki taraf da aynı allow-list'i uygular, tek taraf by-pass'lansa bile
diğeri yakalar.

### 4.5 Testler

1. **`detect_url_kind_http_https`** — `http://x.com`, `https://x.com`,
   `  HTTPS://X.COM` → `Url`; `javascript:alert(1)`, `file:///etc/passwd`,
   boş string, `merhaba dünya`, `http` (şemasız) → `Text`.
2. **`build_introduction_text_url_kind_geçer`** — Regression: `send_text`'in
   URL metni için Introduction frame'i `TextKind::Url`, `text_title` = URL
   preview; düz metin için `TextKind::Text`, generic title.
3. **Integration (loopback)** — sender+receiver aynı süreç içinde loopback;
   `https://example.com` gönder; receiver tarafında `open_url` mock'u /
   `notify.url_opened` i18n key tetiklendiğini doğrula. (Mevcut
   sender-receiver integration test harness'ı varsa oraya ekle; yoksa tek
   unit test yeterli.)

### 4.6 Efor kırılımı

| Adım | Süre |
|---|---|
| `detect_url_kind` + test | 30 dk |
| `send_text` / `build_introduction_text` wire-up | 30 dk |
| Regression test (build_introduction_text_url_kind) | 30 dk |
| Loopback integration (opsiyonel, mevcut harness varsa) | 60–90 dk |
| i18n: `notify.url_sent` vs mevcut key yeterli mi kontrolü | 15 dk |
| README düzeltme (sender tarafı artık URL etiketi gönderiyor) | 15 dk |
| CHANGELOG + PR yazımı | 30 dk |
| **Toplam** | **3–5 saat** |

### 4.7 CLI için not (ertelendi)

`hekadrop send --url https://example.com --to phone` istenen ergonomik bir
arayüz ama HekaDrop bugün clap/subcommand yapısına sahip değil. Bir CLI
yüzeyi açmak:
- clap dependency (≈ 60 KB binary büyümesi, MSRV uyumu kontrolü),
- tray process ile IPC (mevcut webview IPC'yi mi kullanır, named pipe mi?),
- peer selection (isim mi, MAC mi, last-trusted mi?),
- advertise mode etkileşimi

— bu sorular kendi başına bir RFC. **0003-cli-surface.md v0.8+ için**
önerilir; bu RFC'nin scope'unda değildir. v0.7'de kullanıcı URL'i Ctrl+V ile
gönderebiliyor, bu yeterli bir MVP.

## 5. Reviewer için Açık Sorular

1. **`text_title`'a tam URL koymak privacy-OK mi?** URL zaten wire'da bytes
   olarak gidiyor; title ayrıca PII açmıyor. Ama Android "son paylaşımlar"
   ekranında title görünürse hassas URL (token'lı) preview'da kalıcı
   olabilir. Alternatif: yalnızca `scheme://host` preview'ı. **Öneri:
   `url_scheme_host()` helper'ını re-use et** (zaten `log_redact.rs`'de
   mevcut); title'a host koy, tam URL bytes'ta kalsın.
2. **IDN / punycode desteği?** `https://пример.рф` gibi URL'leri detect
   edecek miyiz? `http://`/`https://` prefix kontrolü ASCII-only; IDN ana
   gövdededir, prefix ASCII olduğu için çalışır. Homograf saldırısı
   alıcıda browser'ın sorumluluğu; bizim allow-list'imiz değişmemeli.
3. **`TextType::Address` ve `TextType::PhoneNumber` bir sonraki adım mı?**
   Bu RFC'de değil. Address → `maps://` veya OS harita uygulaması tetiklemek
   isterse ek platform hook gerekir; PhoneNumber → `tel:` şeması.
   Scope-creep'ten kaçınıp 0002'yi URL-only tutuyoruz.
4. **Receiver'da "Copy + Open" action'lı rich notification?** Bugün pasif
   info bildirimi geliyor ve tarayıcı açılıyor. macOS `UNNotificationAction`
   ve Linux `notify-send --action` destekler; bu UX iyileştirmesi ayrı bir
   RFC (0004-rich-notifications) için rezerv.
5. **`detect_url_kind` helper nereye yaşar?** `sender.rs` vs. `connection.rs`
   `is_safe_url_scheme`'in yanı. Önerim: `connection.rs::is_safe_url_scheme`
   pub(crate) yapıp sender'dan çağır — **tek kaynak doğru**, bölünürse ikisi
   zamanla divergent olur. Ya da her ikisi yeni `src/url_scheme.rs` modülüne
   taşınır. Reviewer'a bırakılmış.

## 6. Rollout

- PR scope: `src/sender.rs` + 2 testi + README satır 40-41 revize (artık
  "sender TextType::Url etiketi yollar, alıcı şema doğrular ve açar"
  netlenir) + CHANGELOG.
- Feature flag gerekmez — wire değişikliği geriye uyumlu (eski peer zaten
  `TextType::Url`'ü işleyebiliyordu; yeni peer yollarken aynı enum'u
  kullanıyor, yeni alan yok).
- Android Quick Share ile el-manuel test: macOS HekaDrop'tan
  `https://example.com` paste+send → telefonda URL bildirimi "Aç" butonuyla
  mı görünüyor kontrol.
