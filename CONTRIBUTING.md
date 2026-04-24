# HekaDrop'a katkıda bulunma

HekaDrop topluluk katkılarına açıktır. Hata raporu, özellik önerisi ya da pull request
göndermeden önce lütfen aşağıdaki akışı izleyin.

## Proje yol haritası

HekaDrop, 24 aylık bir yol haritasıyla **v1.0.0 hedef tarihi 2028-04-24** üzerinde ilerliyor.
Tüm major tasarım kararları ve fazları için: [`docs/ROADMAP.md`](docs/ROADMAP.md).
Çeyrek bazlı teslim listeleri ve etiket taksonomisi için: [`docs/MILESTONES.md`](docs/MILESTONES.md).

**Önemli dağıtım politikası:** v1.0.0'a kadar HekaDrop **sadece GitHub Releases üzerinden beta**
olarak yayınlanır. Homebrew Cask, Winget, Scoop, Flathub, Snap, AUR gibi paket yöneticisi
submission'ları v1.0.0'da eş zamanlı yapılacaktır. Bu süre zarfında kendi tap'imizdeki
cask (`yatogamiraito/tap`) freeze durumdadır. Yeni bir paket formatı ekleme PR'ı genel olarak
kabul edilmez; istisnalar için önce issue açıp tartışın.

## RFC süreci

Protokol, public API, yeni crate, yeni bağımlılık (`hekadrop-core` için), güvenlik ilgili
değişiklikler ve platform kararları için önce bir **Request for Comments (RFC)** açılır.
Süreç ve şablon: [`docs/rfcs/README.md`](docs/rfcs/README.md).

- Küçük bir bug fix veya iç refactor için RFC gerekmez.
- Yeni payload tipi, wire format değişikliği, yeni platform desteği ekleme gibi kararlar RFC ister.
- Şüpheliyse RFC aç — maliyeti düşük, belgelemesi değerli.

## Local setup

Once per clone:

```bash
git config core.hooksPath .githooks
```

This enables the pre-commit hook which runs `cargo fmt`, `cargo clippy`,
and `cargo test` before each commit. Skip with `--no-verify` only in
emergencies — CI runs the same checks and will block your PR otherwise.

## İş akışı

1. **Önce issue açın.** Yeni bir özellik / büyük refactor düşünüyorsanız, kod yazmadan
   önce tartışmak hem sizin hem de sürdürücülerin zamanını kurtarır.
2. **Fork + feature branch.** `main`'den ayrılın, anlamlı bir branch adı kullanın
   (ör. `fix/rate-limiter-trusted-bypass`).
3. **Küçük ve odaklı commit'ler.** Bir commit tek bir değişikliği anlatmalı.
4. **Pull request.** CI yeşil olmalı, CHANGELOG.md `[Unreleased]` bölümüne uygun
   alt başlığa (Added / Changed / Fixed / Security) satır ekleyin.

## Bağımlılık güncellik politikası

HekaDrop **agresif güncellik** politikası uygular: prensip olarak her crate'in en son stabil
sürümünü kullanırız. Ancak bazı upstream blokajlar nedeniyle bir dizi bağımlılık eski
sürümde tutulmak zorundadır. Detaylı blocker listesi ve yükseltme sırası:
[`docs/dependency-policy.md`](docs/dependency-policy.md).

**2026-04 itibariyle kritik blokajlar:**

| Crate | Şu anki | Blokaj sebebi |
|---|---|---|
| `tao`, `wry`, `tray-icon` | 0.35 / 0.55 / 0.22 | `webkit2gtk-rs` hâlâ GTK3; GTK4 migration upstream'de WIP |
| `windows` | 0.61 | `wry 0.55` `windows-core` eski sürümüne bağlı; iki farklı `windows-core` trait impl'i çakışıyor |
| `glib-sys` ve GTK3 ailesi (transitif) | eski | Yukarıdaki zincire bağlı; `deny.toml`'da 11 RUSTSEC advisory suppress'li (UI-only path, crypto değil) |

**Kurallar:**
- Yeni bir bağımlılık eklemeden önce `cargo-deny` yeşil olmalı; yeni bir RUSTSEC suppress
  eklenemez (istisna: mevcut GTK3 zinciri).
- Mevcut direct dependency'yi güncelleyen PR'larda changelog'da breaking change olasılığını
  tartışın; semver uyumluluğu transitif düzeyde de kontrol edilir.
- Crypto bağımlılıkları (p256, hkdf, hmac, aes, cbc, cipher, sha2, subtle, elliptic-curve)
  **en güncel minör sürüme** öncelikle güncellenir; major geçişleri RFC ile yapılır.
- Upstream blokaj kalktığında (örneğin wry 0.60+ + GTK4) ilk iş olarak migration PR'ı açılır
  ve tüm zincir yükseltilir.

## Commit mesajı konvansiyonu

Türkçe, imperative (emir kipi) başlık + gerekçeyi anlatan bir `Why:` satırı.
Mevcut repo tarzına uyun.

```
Trusted cihazlar için rate limit bypass'i

Why: Kullanıcının kendi telefonu gibi güvendiği cihazlar throttle'a takılıp
peş peşe gönderimde duraksamamalı. Rate limiter kararı trusted kontrolünden
sonra uygulanacak şekilde taşındı.
```

- Başlık 72 karakteri geçmesin.
- Gövdede neyi değiştirdiğini değil, **neden** değiştirdiğini açıkla.
- Büyük değişikliklerde ilgili issue/PR numarasını referansla (`Refs #42`).

## Commit öncesi kontrol listesi

Commit atmadan önce bu üçü sırayla geçmelidir:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

CI aynı komutları koşar; lokalde yeşile çektiğinizde PR genelde tek seferde geçer.

## Test kapsamı beklentisi

Yeni bir özellik ya da düzeltme için:

- **Unit test** — davranışsal değişiklik olan her fonksiyon için. Saf fonksiyonları
  (crypto, frame, payload assembly) lütfen `#[cfg(test)]` bloklarıyla kapsayın.
- **Integration test** — state machine'i ya da ağ akışını dokunan değişiklikler için
  `tests/` altına senaryo ekleyin (ör. UKEY2 tam tur, reject + cleanup, trusted bypass).
- **Regresyon testi** — `Fixed` kategorisinde bir düzeltme yapıyorsanız, hatayı
  tetikleyen testi de ekleyin; gelecekte yeniden dönmesin.

Kod kapsamı Codecov'a raporlanır; yeni eklenen kodun ortalama kapsamı düşürmemesi beklenir.

## Kod stili

- `cargo fmt` varsayılan profil — manuel düzeltme yok.
- Public API dokümante edilmeli (`///` doc comment); `cargo doc --no-deps` uyarısız geçmeli.
- `unwrap()` / `expect()` yalnızca testlerde veya başlatma-zamanı invariant'larda.
  Production yollarda `?` + `anyhow`/`thiserror`.
- Protokol davranışını değiştiren PR'larda CHANGELOG'da `### Security` ya da
  `### Changed` altına not düşün.

## Claude / AI ajanı katkıları

Bu repoda Claude ajanları iş bölümü ile çalışıyor. Ajan commit'lerinde footer olarak:

```
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

satırı bulunmalıdır. İnsan katkıcılar için bu gerekli değildir.

## Issue etiketleme

HekaDrop'ta tutarlı bir label taksonomisi var: çeyrek (`q1-foundation`, `q2-hardening`, …),
alan (`area:core`, `area:cli`, `area:security`, …), platform (`platform:macos`, …), protokol
(`protocol:quickshare`, `protocol:localsend`, …) ve tip (`type:bug`, `type:feature`, …).
Full liste: [`docs/MILESTONES.md`](docs/MILESTONES.md) § Label Taksonomisi.

Issue açarken lütfen en az bir çeyrek, bir alan ve bir tip etiketi önerin (maintainer
doğrulayacak). Etiketli issue'lar GitHub Projects board'una otomatik düşer.

## Lisans ve DCO

Gönderdiğiniz katkı [MIT lisansı](LICENSE) altında yayımlanır. PR açarak bunu
kabul etmiş sayılırsınız.

v1.0.0 itibariyle **Developer Certificate of Origin (DCO) v1.1** uygulanır ve her commit
`Signed-off-by: Ad Soyad <email@ornek.com>` footer'ı taşır (git -s / --signoff).
v1.0.0'dan önce DCO **opsiyoneldir** ama teşvik edilir — erken yerleşen alışkanlık, geçişi
ağrısız yapar. CLA istemiyoruz; DCO yeterlidir.

DCO metni: https://developercertificate.org/

İyi hacklemeler!
