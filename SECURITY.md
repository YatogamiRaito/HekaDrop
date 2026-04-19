# Güvenlik politikası

## Desteklenen sürümler

Yalnızca son minor sürüm güvenlik düzeltmeleri alır. 0.x serisi "early access"
olduğundan API stabilitesi garanti değil — güvenlik açıkları dışındaki
davranış değişiklikleri minor sürüm bump'ı ile gelebilir.

| Sürüm   | Destek                |
|---------|-----------------------|
| 0.4.x   | ✅ aktif              |
| < 0.4   | ❌ güncelleme yok     |

## Açık bildirme (responsible disclosure)

HekaDrop bir ağ protokolü konuştuğu için güvenlik açıkları ciddi etki
doğurabilir. Lütfen **public issue açmadan** önce bize ulaşın:

- **GitHub Private Vulnerability Reporting** (tercih edilen):
  https://github.com/YatogamiRaito/HekaDrop/security/advisories/new
- **E-posta:** destek@sourvice.com — konu satırına `[HekaDrop security]` yazın

Şunları dahil etmeniz yardımcı olur:

- Etkilenen sürüm(ler) ve işletim sistemi
- Adım adım yeniden üretim (PoC, log, ekran görüntüsü vs.)
- Sizce risk seviyesi ve etki analizi

En geç **72 saat** içinde yanıt vermeyi taahhüt ediyoruz. Kritik bir açık ise
düzeltme hazırlayıp public duyurudan önce sizinle koordine ederiz. CVE
talebine yardımcı oluruz.

## Kapsam

HekaDrop'un çekirdek protokolü Google Quick Share (Nearby Share) tersine
mühendisliğine dayanır. Aşağıdaki sınıflarda raporları değerlendiriyoruz:

- ✅ Rust memory safety (unsafe bloklarında UB, UAF, double-free vb.)
- ✅ Kripto: UKEY2 handshake, AES-CBC HMAC, PIN doğrulama, replay koruması
- ✅ Ağ: mDNS/tcp ile uzaktan kod yürütme, DoS, bellek tüketimi
- ✅ Local: dosya sistemi path traversal, yetki yükseltme
- ✅ Üçüncü parti bağımlılık açıkları (`cargo audit`)

Kapsam dışı:

- Kullanıcı cihazında root/admin erişimi gerektiren saldırılar
- Sosyal mühendislik (PIN'i gönüllü paylaşmak vb.)
- Karşı taraf Android cihazın güvenlik zafiyetleri (Google'a bildirin)

## Teşekkür

Bildirimcinin izniyle `CHANGELOG.md` ve release notes'ta teşekkür ederiz.
