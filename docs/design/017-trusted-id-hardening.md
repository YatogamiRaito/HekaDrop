# Design 017 — Trusted device identity hardening

**Status**: Draft · **Target**: v0.6.0 · **Severity**: HIGH (protocol)
**Refs**: [Issue #17](https://github.com/YatogamiRaito/HekaDrop/issues/17),
`/tmp/research/security.md` (first-round audit)

## 1. Summary

HekaDrop currently binds the "trusted cihaz" list to a cihaz adı + Nearby
`endpoint_id` çifti. `endpoint_id` sadece 4 ASCII bayttır (≈14M kombinasyon)
ve her oturumda peer tarafından rastgele üretilir — kriptografik bağlayıcı bir
kimlik değildir. Saldırgan, kurbanın "trusted" listesinde yaygın bir cihaz
adını hedef alıp (örn. "iPhone 15") sahte bir `endpoint_id` ile eşleşme
yaratarak otomatik kabul yoluna girebilir; bu, v0.5.1'de kapatılan path
traversal'ın trust-bypass yoluyla yeniden tetiklenmesine yol açar (ATO
pattern).

Bu belge, trust kararının **kriptografik olarak sabit bir peer kimliğine**
bağlanmasının protokol, veri modeli, migrasyon ve UX boyutlarını tarif
eder. Hedef: kullanıcının "Kabul + güven" kararı, fiziksel cihaz değişimi
olmadan başka bir peer tarafından devralınamaz olsun.

## 2. Background — threat model

### 2.1 Şu anki akış (vulnerable)

```rust
// connection.rs handle()
let remote_id = cr.endpoint_id.clone().unwrap_or_default();   // 4 byte
let remote_name = parse_remote_name(&endpoint_info);          // arbitrary UTF-8
// ...
let trusted = state::get()
    .settings
    .read()
    .is_trusted(&remote_name, &remote_id);
```

`Settings::is_trusted` kayıttaki `(name, id)` çifti eşleşirse true döner.
`is_trusted` doğru çalışsa bile **zayıf kimlik** üzerinden karar verir.

### 2.2 Saldırgan senaryoları

| # | Saldırı | Etki | Mevcut koruma |
|---|---|---|---|
| T1 | Aynı ağda sahte cihaz adı (kurbanın bildiği isim) | Dialog kullanıcıya sorular; kullanıcı ayırt edemeyebilir ama sistem doğru çalışır | PIN (4-haneli, 10k olasılık) |
| T2 | Trusted listede (name, endpoint_id) çiftini tahmin / brute-force | **Dialog atlanır, otomatik kabul** → dosya sessizce yazılır | Yok |
| T3 | Gerçek trusted cihazın endpoint_id'sini pasif ağ dinlemeyle yakalayıp re-play | T2'nin pratik versiyonu — `endpoint_id` her session'da rastgele olduğundan aynı id geçmişte geçerliyse yeni peer kimliğini sahiplenemez. **İlgili session bitince id anlamsız.** | Session sonu + endpoint_id randomizasyonu |
| T4 | Aynı yerel ağda eş zamanlı iki sahte peer (aynı name, farklı id'ler) | `is_trusted` isim bazlı eşleşse yeterli olacağı için: HEM aynı id ile trust kazananı devralır HEM de farklı id ile görünse bile "known name" olarak UI'ya sızar | Settings'te `(name, id)` çiftli eşleşme (Bug #32 fix, v0.5.0) |

**Katalog sonucu:** pratik ana risk **T2** — trusted listedeki bir kaydın
id'sini tahmin ederek dialog bypass etmek. `endpoint_id` 4 ASCII bayttı;
gerçek hayatta 36^4 ≈ 1.68M kombinasyon (rakam+küçük harf). Bir saldırgan
saniyede ~1 deneme yapsa bile trusted cihazın aktif olmadığı bir pencerede
brute-force uygulanabilir. Rate limiter aynı IP'den 10/60sn sınırı koyar
(non-trusted), ancak saldırgan VPN/proxy chain ile farklı IP'lerden
ilerleyebilir.

Kurbandan gelen **kullanıcı onayı asla bypass'lanmaz** (PIN olmadığı
durumda dialog her zaman gösterilir); T2'nin asıl zararı trust listesine
sızıp **dialog gösterilmeden** kabul yolunu tetiklemektir.

## 3. Goals & non-goals

**Goals:**

1. Trust kararı, cihaz değiştirmediği sürece peer'ın kendini sürekli aynı
   kimlikle doğrulayabildiği bir anahtara bağlansın.
2. Geriye doğru uyum: v0.5.x ile trust edilmiş kayıtlar iki sürüm boyunca
   çalışmaya devam etsin (migration window).
3. Ek saldırı yüzeyi açma: yeni alanlar (hash, signature) eksik / bozuk
   geldiğinde güvenli şekilde "untrusted" davranışa düşsün; handshake
   kararlılığı bozulmasın.
4. UX: Trusted cihaz listesinde görülen ad aynı kalır; kullanıcıdan ek
   aksiyon istenmez. Sadece ilk `add_trusted` anında yeni kimlik yazılır.

**Non-goals:**

1. **Google account tabanlı stable identity** (Google'ın full Quick Share
   protokolünde var). HekaDrop bir sideload client; GAIA entegrasyonu
   scope dışıdır ve HekaDrop'u Google'a bağımlı yapar.
2. **Perfect forward secrecy of trust binding**: trust'a bağlı anahtar
   compromise edilirse geçmiş kararlar geçersiz olur — PFS trust için
   kullanılmaz; bu design security vs. usability dengesi.
3. **Revocation server / CRL infrastructure**: HekaDrop merkezsiz; trust
   iptali "Kullanıcı trusted listeden çıkarır" ile sınırlı.

## 4. Candidate approaches — kaç alternatif

### A. UKEY2 peer pubkey (ephemeral) — **REJECTED**

Peer her session için P-256 anahtar çifti üretir ve `Ukey2ClientFinished`
içinde `GenericPublicKey` olarak gönderir. Bu anahtar ephemeral olduğundan
bir sonraki session'da değişir — **stabil kimlik değildir**. İptal.

### B. PairedKeyEncryption `secret_id_hash` (Google protokolü) — **SEÇILEN**

Quick Share spec'i `PairedKeyEncryption` mesajında `secret_id_hash: [u8; 6]`
ve `signed_data: [u8; 72]` alanları tanımlıyor. Spec'e göre:

- `secret_id_hash` = `HKDF(secret, "public", 6 bytes)` veya benzer bir
  **device-stable** türetme. Cihaz ilk yüklendiğinde deterministik olarak
  türetilir, disk'te saklanır, session'dan bağımsızdır.
- `signed_data` = ECDSA imzası; peer'ın pubkey'inin doğru sahiplendiğini
  kanıtlar. Full doğrulama için peer'ın long-term pubkey'ine erişim gerek.

HekaDrop şu an:

```rust
// connection.rs:861
paired_key_encryption: Some(PairedKeyEncryptionFrame {
    secret_id_hash: Some(random_bytes(6)),  // <- random!
    signed_data: Some(random_bytes(72)),    // <- random!
    ..Default::default()
}),
```

— **bize gelen hash ve imzayı umursamıyor, bizim gönderdiğimiz de random**.
Yani `secret_id_hash` infrastructure spec uyumlu ama hiç kullanılmıyor.

**Plan:** `secret_id_hash`'i **trust kararı için birincil kimlik** yap,
`endpoint_id`'yi yardımcı bilgi seviyesine indir.

### C. Session-scoped trust (TTL) + PIN re-prompt — **KOMPLEMENTER**

Trusted kayıtları 24 saat TTL ile sakla; süre dolduğunda sessizce
"non-trusted" ol, kullanıcıdan tekrar PIN onayı iste. Bu, **trust leak**
yüzeyini zaman boyutunda azaltır — saldırganın tahmin penceresi kısalır.

TTL uzunluğu:
- 24 saat: UX'i en az bozan değer (günlük kullanım modelinde etki yok).
- 7 gün: tamamen "set and forget" UX ama güvenlik azalır.
- Session-only: UX ağır bozulur (her işlemde PIN onayı).

**Plan:** B (hash-based) **+** C'nin 7 gün TTL versiyonu. 7 gün içinde
tekrar kullanıldığında trust yenilenir; aksi halde dialog sorar.

### D. Full pairing exchange — **FUTURE**

Long-term key exchange + out-of-band fingerprint doğrulama (QR kod, yakın
alan). En güvenli ama büyük iş ve Quick Share ekosistemiyle uyumsuz
(peer'lar beklemez). v0.7+ hedefi olarak işaretlendi.

## 5. Protocol integration — B'nin detayları

### 5.1 Bizim tarafımız: `secret_id_hash` nasıl türetilir

Disk tabanlı cihaz-kalıcı kimlik:

```rust
// Yeni dosya: src/identity.rs
//
// İlk çalıştırmada 32 byte random key üret, config dizinine `identity.key`
// olarak 0600 izinle yaz. Sonraki çalıştırmalarda mevcut dosyayı oku.
//
// Bu key'in kendisini PEER'a GÖNDERMEYİZ — sadece hash'ini ve buradan
// türetilen alt-anahtarları.

pub struct DeviceIdentity {
    long_term_key: [u8; 32],   // config'de persist — disk
}

impl DeviceIdentity {
    pub fn load_or_create() -> Result<Self>;

    /// Quick Share PairedKeyEncryption.secret_id_hash (6 byte).
    /// Stabil; cihaz kimliği değişmediği sürece aynı değeri döner.
    pub fn secret_id_hash(&self) -> [u8; 6] {
        let h = hkdf_sha256(
            &self.long_term_key,
            b"HekaDrop v1",
            b"paired_key/secret_id",
            6,
        );
        let mut out = [0u8; 6];
        out.copy_from_slice(&h);
        out
    }

    /// İleride `signed_data` için: ECDSA imza anahtarı türet (şimdi değil).
    #[allow(dead_code)]
    pub fn signing_key(&self) -> [u8; 32] {
        hkdf_sha256(...).try_into().unwrap()
    }
}
```

Yeni dosya yazımı atomic (zaten `atomic_write` helper var). Permissions
POSIX'te 0600, Windows'ta best-effort (NTFS default owner-only yazma).

### 5.2 Peer tarafı: gelen `secret_id_hash`'i nasıl kullanırız

`connection.rs::handle_sharing_frame` içinde
`Some(sh_v1::FrameType::PairedKeyEncryption)` branch'i şu an **yalnızca**
`send_sharing_frame(..., build_paired_key_result())` çağırıyor. Hash'i
kullanmıyor. Değişiklik:

```rust
Some(sh_v1::FrameType::PairedKeyEncryption) if !*sent_paired_result => {
    // YENİ: peer'ın secret_id_hash'ini yakala.
    let peer_hash = v1
        .paired_key_encryption
        .as_ref()
        .and_then(|pke| pke.secret_id_hash.clone())
        .filter(|h| h.len() == 6);
    // `peer_hash` None ise = peer spec'e uymuyor / legacy; kabul et ama
    // trust kararını aşağıda (Introduction branch'inde) sadece
    // (name, endpoint_id) legacy kayıt üzerinden ver.
    *peer_secret_id_hash = peer_hash;
    send_sharing_frame(socket, ctx, &build_paired_key_result()).await?;
    *sent_paired_result = true;
}
```

Introduction branch'inde trust sorgusu:

```rust
// Şu an:
let trusted = settings.is_trusted(remote_name, remote_id);

// Yeni:
let trusted = match &peer_secret_id_hash {
    Some(hash) => settings.is_trusted_by_hash(hash),
    None => settings.is_trusted_legacy(remote_name, remote_id),
};
```

İki ayrı fonksiyon — legacy yol sadece eski kayıtlar için; yeni kayıtlar
hash'siz oluşmaz.

### 5.3 `Settings` şema değişikliği

```rust
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDevice {
    pub name: String,
    pub id: String,            // endpoint_id — legacy, artık tek başına trust anahtarı değil
    #[serde(default)]
    pub secret_id_hash: Option<[u8; 6]>,  // YENI — base64 olarak serialize edilir
    #[serde(default)]
    pub trusted_at_epoch: u64,            // YENI — TTL için
}
```

Geriye uyum:

- Eski JSON (`secret_id_hash` yok) → `None` olarak yüklenir. `is_trusted_legacy`
  aktif — `(name, endpoint_id)` ile eşleşir. Bu kayıt **deprecated** uyarısı
  loglanır ve ilk kullanımda upgrade edilir.
- v0.6.0'da `add_trusted(name, id, hash)` yeni kayıt yazar `hash: Some(...)`.
- v0.7.0'da `is_trusted_legacy` bir uyarı değil **tamamen disabled** olur;
  legacy kayıtlar untrusted davranır.

Migration upgrade noktası: `PairedKeyEncryption` alındığında eğer
`(remote_name, remote_id)` legacy kayıtla eşleşirse **ve** peer hash'i
geldiyse, legacy kaydın `secret_id_hash`'i peer hash ile güncellenir
(opportunistic upgrade, kullanıcıdan izinsiz — çünkü kullanıcı zaten "bu
cihazı güven" demişti).

### 5.4 TTL — 7 gün

`trusted_at_epoch` kaydedilir. `is_trusted_by_hash` şöyle:

```rust
pub fn is_trusted_by_hash(&self, hash: &[u8; 6]) -> bool {
    let now = now_epoch();
    self.trusted_devices.iter().any(|d| {
        d.secret_id_hash.as_ref() == Some(hash)
            && now.saturating_sub(d.trusted_at_epoch) < TRUST_TTL_SECS
    })
}
const TRUST_TTL_SECS: u64 = 7 * 24 * 3600;
```

TTL geçmişse kayıt **silinmez** (kullanıcı ayarları yedeklemiş olsun);
sadece "trusted" sayılmaz. Kullanıcı bir daha dialog'dan "Kabul + güven"
yaparsa `trusted_at_epoch` yenilenir.

### 5.5 `signed_data` doğrulama — **v0.6'da hayır**

`signed_data` alanı peer'ın uzun-süreli private key'iyle imza. Doğrulamak
için peer'ın public key'ine ihtiyaç — peer bunu `PairedKeyEncryption`
içinde göndermiyor. Spec'e göre pubkey ayrı bir "pairing" akışıyla
değiş-tokuş ediliyor (Google account bazlı).

HekaDrop için **v0.6'da signed_data'yı umursamıyoruz** — peer'ın hash'ini
güveniyoruz (bu HMAC değil; ama sadece attacker'ın spoof'lamak istediği
VICTIM cihazının hash'ini bilmesi gerek, ki bu 6 byte × random → tahmin
edilemez değerdir). v0.7'de pairing protokolü eklenirse signed_data ile
**hash + pubkey** bağı kurulur.

**Riski tanımak**: bir attacker kurbanın gerçek trusted cihazının
`secret_id_hash`'ini pasif dinleyerek (PairedKeyEncryption handshake'inde
hash clear-text geçiyor! Secure layer'dan önce) yakalayabilir ve re-play
edebilir. Bu, T3 saldırısının yeni versiyonudur. Kısmen mitigate eden
şey: TTL + hash clear-text olsa da kurbanın handshake'ini aktif dinleme
gerekir (man-in-the-middle). HekaDrop yerel ağ kullandığından tehdit
dar ama gerçek.

Tam mitigation: v0.7'de `signed_data` doğrulamalı long-term keypair +
ilk-kez pairing (QR / PIN). Şimdilik TTL + hash tabanlı.

## 6. Data model + code layout

| Dosya | Değişiklik |
|---|---|
| `src/identity.rs` | YENI — `DeviceIdentity::load_or_create`, `secret_id_hash`, `signing_key` (unused v0.6) |
| `src/settings.rs` | `TrustedDevice` struct genişler; `is_trusted_by_hash`, `is_trusted_legacy`, `add_trusted_with_hash`, `prune_expired` |
| `src/connection.rs` | `handle_sharing_frame` → peer hash capture; Introduction → hash-first trust lookup; `build_paired_key_encryption` → gerçek hash |
| `src/sender.rs` | Sender tarafı da peer hash'ini capture + trust lookup; sender `PairedKeyEncryption` kendi hash'ini gönderir |
| `resources/window.html` (webview) | Trusted listede TTL süresi yaklaşan kayıtlar "X günde son kullanım" gösterir |
| `src/i18n.rs` | Yeni key: `notify.trust_expired`, `webview.trusted.ttl_label` |
| Testler | Settings migrasyon, TTL, is_trusted collision resistance; connection flow integration test |

## 7. Testing plan

### 7.1 Unit

- `DeviceIdentity::load_or_create` idempotency: aynı key döner, dosya
  permission 0600.
- `Settings::is_trusted_by_hash` hash match / mismatch.
- `Settings` TTL: `trusted_at_epoch = now - TRUST_TTL_SECS - 1` → false;
  `= now - TRUST_TTL_SECS + 1` → true.
- Migration: legacy JSON (`secret_id_hash` yok) load → `None`;
  `is_trusted_legacy` hâlâ çalışır.

### 7.2 Integration — **trust hijacking regression**

```rust
// tests/trust_hijack.rs
// Senaryo T2: attacker, kurbanın trusted cihazının (name, endpoint_id)
// çiftini taklit eder ama `secret_id_hash` farklı. v0.6+ trust kararı
// hash'e bağlandığı için dialog gösterilmeli (= otomatik kabul DEĞIL).

#[tokio::test]
async fn trust_is_not_bypassed_by_name_plus_endpoint_id_spoof() {
    // 1) Kurbanın settings'ine (name="Pixel", id="ABCD", hash=[0xAA;6])
    //    kaydet.
    // 2) Sahte sender: (name="Pixel", id="ABCD", hash=[0xBB;6]) ile
    //    PairedKeyEncryption gönderir.
    // 3) Beklenti: Introduction'da `accepted` false (dialog yolu — test
    //    harness'ta dialog otomatik reject dönecek).
}
```

### 7.3 Manuel

- v0.5.2 config.json'ı olan bir dev environment'ta v0.6 çalıştır → log
  uyarısı "legacy trust kaydı — upgrade bekleniyor"; peer ile tekrar
  paired_key exchange yapıldığında kayıt hash ile yükseltilir.
- Trust TTL: sistem saatini 8 gün ileri al → trusted cihaz artık
  dialog soruyor.

## 8. Deployment

### 8.1 Rollout plan

1. **v0.6.0-alpha**: yalnızca `DeviceIdentity` + `secret_id_hash` ürettik,
   peer'lara gönderiyoruz. Trust kararı **hâlâ legacy**. Kullanıcılar test
   eder, kayıt dosyası alanı genişler.
2. **v0.6.0-beta**: Trust kararı `is_trusted_by_hash` öncelikli. Legacy
   kayıtlar opportunistic upgrade olur. UI'da "TTL" bilgisi görünür.
3. **v0.6.0** stable.
4. **v0.7.0**: `signed_data` doğrulama (pairing protokolü) + legacy tamamen
   reddedilir.

### 8.2 Breaking changes

- `Settings` JSON şeması **forward-compatible** — eski sürümler yeni alanları
  yok sayar (serde `#[serde(default)]`).
- Eski versiyona downgrade: v0.6'da yazılmış `secret_id_hash` alanı v0.5'e
  döndüğünde serialize edildiği gibi okunmaz ama fark zararsız (v0.5 yine
  legacy `(name, id)` matchlemeye devam eder).

### 8.3 Security advisory

v0.6.0 release notes **güvenlik advisory'si içerir**:

> [High] Trusted device spoofing via endpoint_id — all v0.5.x and earlier
> releases. v0.5.2 users: upgrade to v0.6.0 and re-confirm trust for known
> devices (opportunistic upgrade on next handshake).

CVE ID ve GHSA draft advisory v0.6.0 release ile publish.

## 9. Açık sorular — review öncesi yanıt gerekli

1. **TTL süresi 7 gün mü, 30 gün mü?** 30 günün UX avantajı var (yılda 12
   kez prompt, yerine 52). 7 gün security-first. Kullanıcı görüşü
   gerekir — belki ayar olsun.
2. **`signed_data` clear-text hash leakage'ı mitigate etmek için hash'i
   ilk-frame sonrası secure layer'dan göndermek mümkün mü?** Quick Share
   spec'e aykırı olur; peer'lar plain `PairedKeyEncryption` bekler.
   Mitigation olarak pairing (v0.7) daha doğru.
3. **Sender tarafında** trust kararını secret_id_hash ile yapmak mantıklı
   mı? Gönderirken peer'ı tanımıyoruz — sadece kullanıcı "gönder" dediği
   cihazı UI'dan seçiyor. Sender'ın "trusted" kavramı daha zayıf (yalnız
   **peer spoofing** değil **kendi peer bilgisini hafızada tutma**
   bağlamında). Sender'da TTL istemeyebiliriz.
4. **Migration log level**: legacy kayıtları `warn!` mi `info!` mi? Üç
   sürüm boyunca yayılacak bir uyarı → `info!` yeterli, kullanıcıyı
   telaşlandırmayalım.
5. **Hash algoritması**: HKDF(long_term_key, "HekaDrop v1", "paired_key/secret_id", 6)
   yerine SHA-256(long_term_key)[..6] yeterli mi? HKDF domain separation
   sağladığı için gelecekte başka hash'ler aynı key'den türetmek güvenli
   olur — **HKDF tercih**.

## 10. Risk register

| Risk | Olasılık | Etki | Mitigation |
|---|---|---|---|
| Migrasyon sırasında kullanıcı trust listesini kaybeder | Düşük | Orta | `#[serde(default)]` + opportunistic upgrade; kayıp yerine "dialog tekrar sorar" |
| `identity.key` silinirse trust listesi anlamını yitirir | Düşük | Yüksek | Backup uyarısı Settings UI'ya ekle; `identity.key` config backup dokümanında işaretli |
| `secret_id_hash` clear-text leaked (T3 variant) | Orta | Orta | TTL + v0.7 signed_data ile çözülür |
| v0.6'da bug — legacy trust her zaman yükselmiyor | Orta | Düşük | Integration test ile önlenir |
| Windows'ta `identity.key` izni `0600` yerine world-readable | Düşük | Yüksek | `atomic_write` dosyayı kapattıktan sonra Windows ACL ile owner-only set — `SetNamedSecurityInfoW` çağrısı gerek; `identity.rs` implementasyonunda test edilecek |

## 11. Implementation checklist

- [ ] `src/identity.rs` — `DeviceIdentity` + `load_or_create` + `secret_id_hash` + unit test
- [ ] `src/settings.rs` — `TrustedDevice.secret_id_hash` + `trusted_at_epoch`; `is_trusted_by_hash`, `is_trusted_legacy`, `add_trusted_with_hash`, `prune_expired`
- [ ] `src/connection.rs` — peer hash capture, hash-first trust lookup, `build_paired_key_encryption` gerçek hash
- [ ] `src/sender.rs` — sender tarafı simetrik değişiklikler (kendi hash'imizi gönder)
- [ ] Migration test: legacy JSON → load → opportunistic upgrade path doğrulama
- [ ] Trust hijack regression test (T2 saldırısı blokage)
- [ ] Windows `identity.key` izin testi (manuel / CI)
- [ ] `i18n.rs` — yeni anahtarlar TR/EN
- [ ] `resources/window.html` — trusted listede TTL bilgisi + data-i18n
- [ ] CHANGELOG + SECURITY.md advisory paragraph
- [ ] GHSA draft (v0.6.0 merge öncesi)

## 12. Sign-off — pre-merge review gerekir

Bu design doc'un 9. bölümdeki açık soruların cevaplanması gerekir
implementation başlatmadan önce. Ayrıca:

- **@YatogamiRaito** sign-off: özellikle TTL süresi + migration log level
- Potansiyel external reviewer (Rust kripto topluluğu / Google Quick
  Share bilen biri): §5.5 signed_data erteleme kararı

Onay sonrası `docs/design/017-trusted-id-hardening.md` status → "Accepted",
Issue #17 implementation PR'ına link verilir.
