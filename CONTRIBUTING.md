# HekaDrop'a katkıda bulunma

HekaDrop topluluk katkılarına açıktır. Hata raporu, özellik önerisi ya da pull request
göndermeden önce lütfen aşağıdaki akışı izleyin.

## İş akışı

1. **Önce issue açın.** Yeni bir özellik / büyük refactor düşünüyorsanız, kod yazmadan
   önce tartışmak hem sizin hem de sürdürücülerin zamanını kurtarır.
2. **Fork + feature branch.** `main`'den ayrılın, anlamlı bir branch adı kullanın
   (ör. `fix/rate-limiter-trusted-bypass`).
3. **Küçük ve odaklı commit'ler.** Bir commit tek bir değişikliği anlatmalı.
4. **Pull request.** CI yeşil olmalı, CHANGELOG.md `[Unreleased]` bölümüne uygun
   alt başlığa (Added / Changed / Fixed / Security) satır ekleyin.

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

## Lisans

Gönderdiğiniz katkı [MIT lisansı](LICENSE) altında yayımlanır. PR açarak bunu
kabul etmiş sayılırsınız.

İyi hacklemeler!
