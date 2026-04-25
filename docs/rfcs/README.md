# HekaDrop RFC Süreci

Request for Comments (RFC) — HekaDrop'ta önemli teknik kararların yazıya dökülme, gözden geçirilme ve kabul edilme süreci. Her RFC, implementasyon öncesi tasarım kararını ve neden/nasıl sorularını cevaplar; implementasyon sonrası da tarihsel referans olarak kalır.

## Ne zaman RFC yazılır?

Zorunlu:
- **Public API değişikliği** `hekadrop-core` crate'inde (v0.7.0 sonrası semver garantilidir)
- **Protokol değişikliği** — wire format, handshake akışı, yeni payload tipi
- **Yeni crate** workspace'e eklenmesi
- **Yeni bağımlılık** (direct) `hekadrop-core` için — supply chain etkisi var
- **Güvenlik ilgili değişiklik** — crypto seçimi, trust store formatı, permission modeli
- **Platform kesicisi** — yeni işletim sistemi desteği veya bir platformun desteğinin kaldırılması
- **Yayın/dağıtım politikası** değişiklikleri (örneğin paket yöneticisi submission zamanı)

RFC gerekmez:
- Bug fix (tests yeterli)
- Refactor (aynı davranışı koruyorsa)
- Dependency patch/minor bump (major bump gerektirir)
- Dokümantasyon güncellemesi
- UI string değişikliği
- i18n ekleme

**Şüpheliyse:** RFC aç. Maliyeti düşük, belgelemesi değerli.

## Numaralandırma

RFC'ler sıfırdan başlayan 4 haneli numara alır:
- `0000` — meta/template
- `0001` — ilk gerçek RFC
- `NNNN` — sıradaki numara

Numarayı yazmadan önce `ls docs/rfcs/` ile en yüksek numarayı bul, bir artır. Çakışma olursa merge sırasında düzenle.

Dosya adı: `NNNN-kisaca-ne-hakkinda.md` (kebab-case, küçük harf).

## Şablon

Yeni bir RFC açarken `docs/rfcs/0000-template.md` dosyasını kopyala. Bölümler:

```markdown
# RFC NNNN — <başlık>

- **Başlatan:** @kullanici
- **Durum:** Draft | In Review | Accepted | Rejected | Superseded by NNNN | Withdrawn
- **Oluşturulma tarihi:** YYYY-MM-DD
- **Hedef sürüm:** v0.x.0
- **İlgili issue:** #N (varsa)

## Özet
Tek paragrafta bu RFC'nin önerisi.

## Motivasyon
Neden şimdi? Hangi problem çözülüyor? Hangi hedef bu RFC olmadan ulaşılamaz?

## Ayrıntılı tasarım
Uygulayan kişinin RFC'yi ilk kez okuduğunda ek araştırma yapmadan kodu yazabileceği detay seviyesi.

## Alternatifler
Değerlendirilen ve reddedilen seçenekler + red sebebi.

## Geriye uyumluluk / migration
Var olan kod, kullanıcı, protokol peer'ları üzerindeki etki. Migration yolu.

## Güvenlik değerlendirmesi
Yeni bir attack surface mi açıyor? Threat model'in hangi bölümünü etkiliyor?

## Performans değerlendirmesi
Ölçülebilir etki, benchmark veya tahmin.

## Açık sorular
Karar verilmemiş noktalar; gözden geçirenlere sorular.

## Referanslar
Standart, başka RFC, araştırma dokümanları.
```

## Yaşam döngüsü

1. **Draft** — yazar branch'te hazırlar. Commit'ler dolaylı, tek atom gerekmez.
2. **In Review** — `main`'e PR açılır, etiket `rfc:review`. Herkes yorum yapabilir.
3. **Decision** — iki iş günü minimum review penceresi. Maintainer konsensüsüyle:
   - **Accepted** — merge edilir; `Durum:` güncellenir.
   - **Rejected** — merge edilmez veya "rejected" bölümüyle merge edilir (arşiv).
   - **Withdrawn** — yazar geri çeker.
4. **Superseded** — yeni bir RFC eskisini değiştiriyorsa, eski RFC'nin başına `Superseded by NNNN` notu.

RFC reddedilse bile dosya silinmez; gelecekteki tartışmalar için referans kalır. Sadece `Durum:` alanı güncellenir.

## Implementasyon

Accepted RFC'nin implementasyonu ayrı PR(lar)da yapılır. Her implementation PR'ı başlığında "implements RFC-NNNN" referansı ister. Büyük RFC'ler birden fazla PR'a yayılabilir (workspace refactor gibi); her PR bir "step"e karşılık gelir, RFC'deki migration planında listelenir.

Implementation ilerledikçe RFC dokümanı **genellikle değiştirilmez**; değiştirilmesi gerekiyorsa yeni RFC açılır ve "Superseded" işareti konur. Tek istisna: "Durum" değişikliği.

## Rol sorumlulukları

- **Yazar:** RFC'yi hazırlar, geri bildirimlere cevap verir, gerektiğinde revize eder.
- **Reviewer:** Tasarımı eleştirir, alternatif sorgular, implementasyon gerçekleştirilebilirliğini test eder.
- **Maintainer:** Son kararı verir (accept/reject), merge eder.

## Üslup

- Türkçe gövde, kod/komut/standart adı İngilizce (projenin genel kuralı).
- Her RFC bağımsız okunabilir olmalı; prior knowledge varsaymayın.
- Karar vermekten kaçınmayın — "açık soru"lar olabilir ama RFC'nin iskeleti bir yön önermelidir.
- Somut kod örnekleri kullanın; API imzaları, dosya yolları, satır numaraları.

## Örnekler

İyi bir RFC ne kadar uzun olmalı?
- Basit bir ekleme (yeni CLI flag, yeni locale): **300-800 kelime** yeterli.
- Orta karmaşık (yeni payload tipi, yeni protokol mesajı): **1000-2500 kelime**.
- Büyük tasarım (workspace refactor, dual-protocol receiver): **2500-5000 kelime**.

Uzunluk değil, kapsanmayan durum sayısı minimum olmalı.

## Sık yapılan hatalar

- "Motivasyon"u atlamak → gelecekteki okuyucu kararı anlamaz.
- "Alternatifler"i listelememek → başka biri aynı alternatifleri tekrar araştırır.
- Implementasyon adımlarını çok üst seviye bırakmak — hedef: implement eden kişi RFC'yi okuyup kodu yazabilmeli.
- RFC yazarken ses "ben bunu yapacağım" olmalı, "bu belki yapılabilir" değil.
- Güvenlik bölümünü "N/A" diye geçmek — en azından "bu RFC saldırı yüzeyi eklemiyor çünkü ..." diye açıklanmalı.

---

## Mevcut RFC dizini

Bu dizin otomatik güncellenmez. Yeni RFC eklendiğinde aşağıya ekleyin.

| # | Başlık | Durum | Sürüm |
|---|---|---|---|
| 0001 | Workspace refactor | Draft | v0.7.0 |
| 0002 | URL payload decision | Accepted (implemented in bb2cedf + 393c74c) | v0.7.0 |
| 0003 | Chunk-level HMAC-SHA256 | Draft | v0.8.0 |
| 0004 | Transfer resume | Draft | v0.8.0 |
| 0005 | Folder payload (HEKABUND) | Draft | v0.8.0 |

---

İlgili dokümanlar:
- [ROADMAP.md](../ROADMAP.md) — 24 aylık v1.0.0 yol haritası
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — genel katkı kılavuzu
- [SECURITY.md](../../SECURITY.md) — güvenlik bildirimi süreci
