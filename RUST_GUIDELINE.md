# Rust Kod Kalitesi, Performans ve Optimizasyon Talimatları (v1 — Rust 2024/2026)

> **HEDEF SÜRÜM:** Rust **1.90+** ve **Rust 2024 Edition**. Tüm öneriler modern Rust pratikleriyle tam uyumludur.

> **TALİMAT:** Aşağıdaki kuralları **sırasıyla** uygula. Her adım için Rust modülünü veya dosyasını analiz et ve gerekli değişiklikleri yap.
> İşlem bittiğinde, üzerinde değişiklik yaptığın **her dosyanın güncellenmiş TAM kodunu** tek seferde kopyalanabilir kod bloklarında sun. Diff/yama (patch) verme, kodun tamamını ver.

> **ÖNCELİK PRENSİBİ:** "Önce ölç, sonra optimize et" yaklaşımını benimse. Gereksiz unsafe veya aşırı soyutlamalardan kaçın; her optimizasyonun somut bir bellek/performans veya kod güvenliği sebebi olmalıdır.

> **RUST 2024 / 1.90+ GÜNCELLEMESİ:** Rust 2024 ile birlikte yerleşik `AFIT` (Async Fn in Trait) ve `RPITIT` (Return Position Impl Trait in Trait) tamamen kararlıdır. Ayrıca **Async Closures** (`async || {}`) ve **Precise Capturing** (`use<'a, T>`) mekanizmaları dilin yerleşik birer parçasıdır. Bu talimatlar bu modern yetenekleri en üst düzeyde kullanacak şekilde optimize edilmiştir.

---

## ⛔ PROJE STANDARTLARI (MUTLAK KURALLAR)

1. **Modül Yapısı ve Görünürlük Hijyeni (Visibility):**
   - Private modüllerden dışarıya gereksiz sızmaları engellemek için `unreachable_pub` kuralını enforce et. `pub` yerine her zaman `pub(crate)` veya `pub(in crate::...)` tercih et.
2. **Kullanıcı Hata Mesajları:**
   - Toast/UI'a veya CLI'a yansıyan tüm kullanıcı dostu hata mesajları **Türkçe** olmalıdır. Rust hata tanımları veya loglar İngilizce kalabilir, ancak son kullanıcıya dönen hatalar Türkçe olmalıdır.
3. **Yasaklar (Strict Denies):**
   - `dbg!` makrosunu production kodunda kullanma (`dbg_macro = "deny"`).
   - `print!` veya `eprint!` makrolarını library/core modüllerde kullanma, yerine `tracing::info!`, `tracing::warn!`, `tracing::error!` kullan (`print_stdout = "warn"`).
   - `.unwrap()` veya `.expect()` veya `panic!` kullanma (`unwrap_used = "warn"`, `expect_used = "warn"`). Bunun yerine `Result` veya `Option` combinator'larını (`map_or`, `unwrap_or_else`, `ok_or`) ve `?` operatörünü kullan.
4. **Unsafe Blok Disiplini (Rust 2024 Güncellemesi):**
   - Projede `unsafe` blok kullanılıyorsa, her blok üzerinde `// SAFETY: <açıklama>` yorum satırı bulunması zorunludur. `unsafe_op_in_unsafe_fn` her zaman "deny" edilmelidir.
   - Rust 2024 gereği; `extern` blokları artık `unsafe extern` olarak bildirilmelidir. Ayrıca `export_name`, `link_section` ve `no_mangle` attribute'ları yalnızca `unsafe` bağlamlarda veya güvenlik audit'i ile kullanılmalıdır.

---

## ADIM 1: Kullanılmayan Import'ları ve Ölü Kodları Sil

Dosyanın en başındaki her `use` satırı için, import edilen her modül, struct, enum, trait veya fonksiyonun dosyanın geri kalanında **gerçekten kullanılıp kullanılmadığını** kontrol et.

**Kontrol yöntemi:**
- Import edilen ismi dosyanın tamamında ara.
- Sadece import satırında geçiyorsa veya sadece kullanılmayan test bloklarında kalmışsa → **sil**.
- Dış bağımlılıkların kullanılmayan feature'larını veya atıl kalmış `dead_code` bloklarını kaldır.

```rust
// ⛔ KÖTÜ — Kullanılmayan TcpListener ve unused_import uyarısı
use tokio::net::{TcpStream, TcpListener};

// ✅ İYİ — Sadece kullanılanları import et
use tokio::net::TcpStream;
```

---

## ADIM 2: Görünürlük Hijyeni (pub -> pub(crate))

API yüzeyini olabildiğince daralt. Workspace refactor sonrası, bir struct veya fonksiyon sadece o crate içinde kullanılıyorsa `pub` anahtar kelimesini `pub(crate)` ile değiştir.

**Neden kritik?**
- `unreachable_pub` linti ile uyumluluk sağlar.
- Derleyicinin (rustc) ölü kod analizini ve dead-code elimination (DCE) süreçlerini optimize eder.
- Gelecekteki semver breaking change risklerini en aza indirir.

```rust
// ⛔ KÖTÜ — Dışarıdan erişilmeyen gereksiz public yapı
pub struct SessionManager {
    pub session_id: String,
}

// ✅ İYİ — Crate seviyesinde sınırlandırılmış görünürlük
pub(crate) struct SessionManager {
    pub(crate) session_id: String,
}
```

---

## ADIM 3: Async/Sync Karışıklığı ve Gereksiz Async'leri Kaldırma

Fonksiyonların gövdesini analiz et. İçinde hiçbir `.await` çağrısı barındırmayan veya asenkron bir operasyon tetiklemeyen fonksiyonları sync'e dönüştür (`unused_async = "warn"`).

**Neden kritik?**
- Asenkron durum makineleri (State Machines) derleme zamanında ekstra overhead yaratır.
- Gereksiz `async fn` kullanımı, caller tarafında zorunlu `.await` ve poll maliyeti oluşturur.

```rust
// ⛔ KÖTÜ — İçinde .await olmayan gereksiz async fonksiyon
pub async fn verify_chunk_tag(chunk: &[u8]) -> bool {
    chunk.len() > 4 && chunk[0] == 0xCC
}

// ✅ İYİ — Doğrudan sync fonksiyon
pub fn verify_chunk_tag(chunk: &[u8]) -> bool {
    chunk.len() > 4 && chunk[0] == 0xCC
}
```

> **⚠️ BLAZER TIP:** Async runtime (Tokio) içinde çalışırken bloklayıcı (blocking) I/O (örneğin `std::fs` veya `std::thread::sleep`) yapmaktan kaçın. Eğer blocking işlem kaçınılmazsa, bunu `tokio::task::spawn_blocking` ile sarmala.

---

## ADIM 4: Kopya (Clone) ve Allocation Optimizasyonu

Heap allocation gerektiren `String`, `Vec` gibi tiplerin gereksiz yere kopyalanmasını (`.clone()`) önle.

**Uygulanacak Kurallar:**
1. **Redundant Clone:** Bir değer sahipliğini (ownership) taşımak (move etmek) mümkünse clone yapma.
2. **Copy Tipler:** `Copy` trait'ine sahip tipler üzerinde `.cloned()` yerine `.copied()` kullan (`cloned_instead_of_copied`).
3. **Implicit Clone:** `.to_owned()` yerine daha belirgin olan `.clone()` kullan.
4. **Büyük Parametreler:** Stack'te 256 byte'tan büyük yer kaplayan tipleri by-value geçirmek yerine referans (`&T`) ile geçirmeyi tercih et (`large_types_passed_by_value`).

```rust
// ⛔ KÖTÜ — Gereksiz heap allocation ve string kopyalama
fn process_settings(name: String) -> String {
    let name_clone = name.clone();
    format!("User: {}", name_clone)
}

// ✅ İYİ — Sahipliği taşıma (Move semantics)
fn process_settings(name: String) -> String {
    format!("User: {}", name)
}
```

---

## ADIM 5: `thiserror` ve `anyhow` ile Hata Yönetimi Disiplini

Hata yönetimini katmanlara göre ayır:
- **Core / Library Modülleri:** Dışarıya tahmin edilebilir ve spesifik hatalar sunmak için `thiserror` (v2.0+) kullan.
- **Application / CLI Seviyesi:** Hızlı hata toplama ve context ekleme için `anyhow` kullan.

**Kurallar:**
1. Hataları sessizce yutma (`map_err_ignore`). Hata oluşuyorsa bunu tracing veya log mekanizmasıyla yakala ya da üst katmana fırlat.
2. `.unwrap_or()` içindeki varsayılan değer pahalı bir hesaplama veya allocation gerektiriyorsa, bunu lazy olan `.unwrap_or_else(|| ...)` ile değiştir.

```rust
// ✅ İYİ — thiserror v2 ile idiomatik kütüphane hatası tanımlama
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("Geçersiz frame formatı: {0}")]
    InvalidFrame(String),

    #[error("I/O Hatası: {0}")]
    Io(#[from] std::io::Error),
}
```

---

## ADIM 6: Sayısal Dönüşümlerde strict cast (`as` yerine `TryFrom`)

Tamsayı veya kayan noktalı sayı dönüşümlerinde doğrudan `as` operatörü kullanırken dikkatli ol. Truncation veya sign loss riski taşıyan dönüşümleri `TryFrom` ile güvenli hale getir.

**Hedef alanlar:**
- `cast_possible_truncation`: `usize as u32` (özellikle 64-bit mimarilerde taşma riski).
- `cast_possible_wrap`: `u32 as i32` (işaretli/işaretsiz dönüşümde wrap riski).
- `cast_sign_loss`: `i32 as u32`.

**DÖNÜŞTÜR:**
- `value as u32` → `u32::try_from(value).map_err(...)` veya `u32::from(b)` (eğer kayıpsız ise).

```rust
// ⛔ TEHLİKELİ — Taşma durumunda veri kaybı riski
let size_u32 = data.len() as u32;

// ✅ GÜVENLİ — Taşma durumunda hata yönetimi
let size_u32 = u32::try_from(data.len()).map_err(|_| ProtocolError::InvalidFrame("Boyut çok büyük".into()))?;
```

---

## ADIM 7: Bellek ve Mutex Optimizasyonu (`parking_lot`)

Static veya zero-allocation gerektiren yerlerde asenkron kilitler yerine `parking_lot` kütüphanesinin `Mutex` veya `RwLock` yapılarını tercih et.

**Kurallar:**
1. **Async Mutex vs Sync Mutex:** Kilidi bir `.await` sınırı boyunca tutman gerekmiyorsa, asla `tokio::sync::Mutex` kullanma. Yerine `parking_lot::Mutex` kullan.
2. **Heap Indirection Azaltma:** Eğer bir fonksiyonun dönüş değeri heap allocation gerektirmiyorsa direkt stack'te `T` dön, `Box<T>` kullanımından kaçın (`unnecessary_box_returns`).

```rust
// ⛔ KÖTÜ — Gereksiz asenkron kilit ve await overhead'i
use tokio::sync::Mutex;
async fn update_stats(stats: &Mutex<Stats>) {
    let mut lock = stats.lock().await;
    lock.total_bytes += 1024;
}

// ✅ İYİ — Senkron, ultra hızlı parking_lot::Mutex
use parking_lot::Mutex;
fn update_stats(stats: &Mutex<Stats>) {
    let mut lock = stats.lock();
    lock.total_bytes += 1024;
}
```

---

## ADIM 8: Deadlock ve Döngü Denetimi (Concurrency)

Birden fazla kilidin (lock) alındığı senaryolarda kilit sırasını (lock ordering) netleştir.

### Kontrol Listesi:
1. **Nested Lock Önleme:** `let _guard1 = lock1.lock();` altındayken `lock2.lock();` çağrısı yapılıyorsa deadlock riskini analiz et.
2. **tokio::select! ve Cancellation Safety:** `tokio::select!` bloğundaki branch'lerin iptal edilmeye karşı güvenli (cancellation-safe) olduğundan emin ol. I/O operasyonlarında yarım kalmış frame riski varsa buffer'ları muhafaza et.
3. **Sonsuz Döngü Koruması:** `loop` veya `while let` bloklarında, çıkış (break) koşulunun her zaman tetiklenebileceğini doğrula.

---

## ADIM 9: Bellek Sızıntısı (Memory Leak) ve Resource Cleanup

Asenkron süreçlerde gracefully shutdown ve iptal (cancellation) mekanizmalarını doğru kurgula.

### Cleanup GEREKLİ olan senaryolar:

| Senaryo | Cleanup / Çözüm Yöntemi |
|---------|-------------------------|
| Arka planda koşan asenkron loop'lar | `tokio_util::sync::CancellationToken` |
| Manuel kaynak yönetimi (RAII) | `Drop` trait implementation |
| Drop Guard'ların yönetimi | İsmi `_` ile başlayan değişkenler anında drop edilir. Token veya Guard'ların yaşaması isteniyorsa adlandırılmış değişken kullan (`used_underscore_binding`). |

```rust
// ⛔ TEHLİKELİ — _guard anında drop edilir, kilit korunmaz!
let _guard = lock.lock();

// ✅ GÜVENLİ — Değişken adlandırılarak scope sonuna kadar yaşatılır
let guard = lock.lock();
```

---

## ADIM 10: Iterator ve Collection Mikro-Optimizasyonları

Iterator zincirlerindeki ara heap allocation'ları ve gereksiz döngü turlarını ortadan kaldır.

**Kurallar:**
1. **Needless Collect:** `.collect::<Vec<_>>().len()` yerine doğrudan `.count()` kullan (`needless_collect`).
2. **Flat Map:** `.map(...).flatten()` yerine tek geçişli `.flat_map(...)` veya `.filter_map(...)` kullan.
3. **Map Unwrap:** `.map(f).unwrap_or(d)` yerine `.map_or(d, f)` tercih et (`map_unwrap_or`).
4. **Unstable Sort:** Primitive veri dilimlerini (slice) sıralarken kararlı (stable) `.sort()` yerine çok daha hızlı olan `.sort_unstable()` tercih et (`stable_sort_primitive`).

```rust
// ⛔ KÖTÜ — Ara Vec oluşturulur ve bellek tahsis edilir
let active_count = items.iter().filter(|x| x.is_active).collect::<Vec<_>>().len();

// ✅ İYİ — Sıfır allocation, tek geçiş
let active_count = items.iter().filter(|x| x.is_active).count();
```

---

## ADIM 11: Kod Okunabilirliği ve Erken Çıkış (Let-Else & Early Return)

Rust 1.65+ ile gelen `let-else` yapısını kullanarak iç içe geçen (nested) `if let` bloklarını flat hale getir.

```rust
// ⛔ KÖTÜ — Derin nesting, sağa doğru kayan kod
if let Some(session) = active_session {
    if session.is_valid() {
        process_session(session);
    }
}

// ✅ İYİ — let-else ile erken çıkış (Flat control flow)
let Some(session) = active_session else { return };
if !session.is_valid() { return; }
process_session(session);
```

### Redundant Else Temizliği:
```rust
// ⛔ KÖTÜ
if condition {
    return Ok(true);
} else {
    Ok(false)
}

// ✅ İYİ — Early return
if condition {
    return Ok(true);
}
Ok(false)
```

---

## ADIM 12: Modern Rust 2024 Yerleşik Trait'leri (AFIT & Async Closures)

Rust 2024 ile birlikte asenkron programlama yetenekleri yerleşik dil yapılarına kavuşmuştur:
1. **Async Fn in Trait (AFIT):** Trait'lerde asenkron metotlar tanımlamak için `#[async_trait]` makrosuna ihtiyaç kalmamıştır. Doğrudan yerleşik `async fn` kullan. Bu sayede gereksiz `Boxed Future` ve heap allocation'lar sıfırlanır.
2. **Async Closures (`async || {}`):** Eski `|| async { ... }` kalıbı yerine dil düzeyinde desteklenen asenkron closure'ları kullan. Bu sayede closure içerisindeki local environment referansları borrow-checker engeline takılmadan güvenle yakalanır. Prelude'a eklenen `AsyncFn`, `AsyncFnMut` ve `AsyncFnOnce` trait'lerini callback sınırlarında tercih et.

```rust
// ⛔ ESKİ — async-trait makrosu ile (Runtime heap allocation / Boxed Future)
#[async_trait]
pub trait Storage {
    async fn read_data(&self) -> Result<Vec<u8>>;
}

// ✅ YENİ — Rust 2024 yerleşik AFIT (Sıfır maliyet, statik dispatch uyumlu)
pub trait Storage {
    async fn read_data(&self) -> Result<Vec<u8>>;
}

// ✅ YENİ — Yerleşik Async Closure Kullanımı
let process_payload = async |data: &[u8]| {
    // Closure captures environmental variables properly
    analyze(data).await;
};
```

---

## ADIM 13: Hassas Yaşam Süresi Yakalama (Precise Capturing — `use<'a, T>`)

Rust 2024'te, `impl Trait` (opaque types) dönüş türleri varsayılan olarak kapsam içindeki tüm tip ve lifetime parametrelerini otomatik yakalar (overcapturing). Gereksiz borrow checker kısıtlamalarını ve yaşam süresi çatışmalarını önlemek için `use<...>` hassas yakalama syntax'ını tercih et.

**Neden kritik?**
- Fonksiyonun döndürdüğü opaque tip (örneğin asenkron bir `Future`), aslında kullanmadığı bir fonksiyona ait referansın ömrünü (`'a`) gereksiz yere kilitlemez.
- Kodun generic esnekliğini artırır.

```rust
// ✅ İYİ — use<...> ile sadece `'a` ve `T` parametrelerini capture et,
// `U` parametresinin referansını serbest bırak (overcapturing önlendi)
fn process_stream<'a, T, U>(x: &'a T, y: U) -> impl Future<Output = ()> + use<'a, T> {
    async move {
        // Yalnızca x ve T ile çalışır, U serbesttir.
    }
}
```

---

## 🚀 PROJE AMACINA ÖZEL OPTİMİZASYONLAR (GOOGLE QUICK SHARE & LAN TRANSFER)

HekaDrop projesi, Google Quick Share protokolünün yüksek hızlı ve güvenli yerel dosya transferi (LAN) gerçekleştiren bir implementasyonudur. Bu amaca yönelik modülleri optimize ederken aşağıdaki kuralları uygula:

### A. Şifrelemede Donanım Hızlandırma (Hardware AES-NI & Neon)
HekaDrop her payload ve veri bloğunu AES-256-CBC şifrelemesi ve HMAC-SHA256 bütünlük kontrolüyle taşır. Bu kriptografik işlemler yerel ağ hızlarında (Gigabit+) CPU darboğazı yaratmamalıdır.
* **Kural:** RustCrypto kütüphaneleri varsayılan olarak CPUID ile çalışma zamanı (runtime) AES-NI veya Neon hızlandırmasını dener. Ancak, dağıtılan binary performansını garanti altına almak ve derleyicinin donanım seviyesinde optimizasyon yapmasını sağlamak için build flag'lerine explicit komut seti desteği ekle:
  - **x86_64 target:** `.cargo/config.toml` dosyasına `rustflags = ["-C", "target-feature=+aes,+ssse3"]` ekle.
  - **ARM64 / Apple Silicon target:** `.cargo/config.toml` dosyasına `rustflags = ["-C", "target-feature=+neon"]` ekle.
* Donanım tabanlı hızlandırma, CBC şifreleme/deşifreleme süresini 10 kata kadar düşürür ve aktarım sırasında CPU kullanımını minimize eder.

### B. UKEY2 Handshake ve Zamanlama Güvenliği (Constant-Time Operations)
UKEY2 el sıkışma aşamasında 4 haneli doğrulama PIN'leri ve kriptografik HMAC imzaları karşılaştırılır.
* **Kural:** Karşılaştırma işlemlerinde **asla** standart `==` veya `!=` operatörlerini kullanma. Bu operatörler ilk uyuşmayan karakterde sonlandığı için milisaniyelik zamanlama farkları (timing attacks/leaks) sızdırır.
* Bunun yerine `subtle` crate'inin `ConstantTimeEq` trait'ini zorunlu kıl. Karşılaştırma işlemlerinin her zaman sabit sürede tamamlanmasını garanti altına al.

```rust
// ⛔ KÖTÜ — Zamanlama saldırılarına karşı korumasız (Timing Leak)
if received_auth_string == computed_auth_string { ... }

// ✅ İYİ — subtle::ConstantTimeEq ile güvenli sabit zamanlı karşılaştırma
use subtle::ConstantTimeEq;
if received_auth_string.ct_eq(&computed_auth_string).unwrap_u8() == 1 { ... }
```

### C. Zero-Copy Network & Buffer Pooling (Disk-Network I/O)
Yerel ağda gigabaytlarca dosya taşırken sürekli yeni `Vec<u8>` veya `BytesMut` buffer'ı tahsis etmek bellek fragmentasyonuna ve yavaşlamaya neden olur.
* **Kural:** Dosya okuma ve yazma işlemlerinde `tokio::io::copy` kullan.
* Protobuf mesajlaşmalarında (`prost`) veya chunk frame serileştirmelerinde buffer'ları her seferinde sıfırdan oluşturmak yerine, `clear()` çağrısı ile kapasitesini koruyarak yeniden kullan (buffer pooling/reuse).

### D. Masaüstü Tray Uygulaması Bellek Hijyeni (Tray App Memory Footprint)
HekaDrop menü barında sessizce ve sürekli arka planda çalışan bir tray uygulamasıdır. Bellek sızıntısı yapmaması ve minimum ram tüketmesi kritik önemdedir.
* **Kural:** Bellek fragmentasyonunu azaltmak için platforma özgü modern thread-safe bellek tahsis edicileri (`mimalloc` veya `jemalloc`) `main.rs` seviyesinde global allocator olarak tanımla.
* Release profilindeki boyut sıkıştırması (`opt-level = "z"`, `codegen-units = 1`, `lto = true`) optimizasyonlarını koru.

```rust
// ✅ İYİ — mimalloc entegrasyonu ile kararlı ve düşük RAM tüketimi
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

---

## ÇIKTI FORMATI

Tüm adımları Rust dosyasına uyguladıktan sonra şu formatta çıktı ver:

### 1. Güncellenmiş Dosyaların TAM Kodu
(Dosyaların güncellenmiş tüm içeriğini kopyalanabilir tek bir kod bloğunda sun).

### 2. Değişiklik Özeti Tablosu

| Dosya | Adım | Yapılan Değişiklik | Satır No |
|-------|------|-------------------|----------|
| ... | ... | ... | ... |

### 3. Yaşam Süresi ve Sahiplik (Lifetime & Ownership) / Borrow Checker Analiz Raporu

Her referans ve kopyalama işlemi için:

```
[DOSYA] veriTipi veya değişken
  Kopya (Clone) Nedeni: Sahiplik transferi / Referans ömrü yetersizliği
  Optimizasyon: Sahiplik taşındı (Move) / Referansa dönüştürüldü / Zaten optimum
  Referans Ömrü (Lifetime) / Capture: 'static / Precise Capture (use<'a, T>)
```

### 4. Async & Concurrency / Döngü / Deadlock Denetim Raporu

Her asenkron kilit ve loop için:

```
[DOSYA] Mutex / Loop satır XX
  Kilit Tipi: parking_lot::Mutex / tokio::sync::Mutex
  Döngü Riski / Deadlock Analizi: Kilit sıralaması güvenli / Async sınırları dışında kilit bırakma mevcut değil
  Cancellation Safety Durumu: GÜVENLİ / KORUMALI (CancellationToken ile)
```

### 5. Clippy Pedantic Batch İnceleme & Fix Raporu

```
[DOSYA] Clippy Linti satır XX
  Lint Kategorisi: cast_possible_truncation / map_unwrap_or / stable_sort_primitive / vb.
  Yapılan Düzeltme: TryFrom dönüşümü uygulandı / map_or'a çevrildi / sort_unstable yapıldı
```

### 6. Error Handling & Panic Önleme Raporu

```
[DOSYA] Result/Option Tipi satır XX
  Hata Yönetim Stili: thiserror / anyhow / ? Operatörü
  Panic/Unwrap Riski: YOK (Tüm unwrap'ler safe combinator'lar veya expect ile değiştirildi)
  Türkçe Hata Mesajı Uyumluluğu: EVET
```
