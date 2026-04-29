# HekaDrop Protokol Dokümantasyonu

Bu dizin, HekaDrop'un konuştuğu protokollerin **wire-level** spesifikasyonlarını içerir.
Farklı bir implementasyon yazacak kişinin (başka dilde reimplementation, fuzzer geliştirici,
güvenlik denetçisi) ek araştırma yapmadan okuyup uygulayabileceği detay seviyesi hedeflenir.

## Taban protokoller (upstream)

Aşağıdakiler Google / LocalSend topluluklarının spec'leri. Biz konuşuyoruz ama biz yazmadık:

- **Quick Share / Nearby Connections** — upstream Google, resmi spec yok; reverse-engineered
  referans: [grishka/NearDrop/PROTOCOL.md](https://github.com/grishka/NearDrop/blob/master/PROTOCOL.md),
  [Martichou/rquickshare/core_lib](https://github.com/Martichou/rquickshare/tree/master/core_lib).
  Kullandığımız protobuf tanımları `proto/` dizininde (device_to_device_messages, offline_wire_formats,
  securegcm, sharing, ukey, wire_format).
- **LocalSend v2** — [localsend/protocol](https://github.com/localsend/protocol). v0.15.0'da
  (ROADMAP §Q5 çeyreği, 2027-05 → 2027-07) implement ediliyor.

## HekaDrop-spesifik uzantılar

Aşağıdakiler HekaDrop'un Quick Share'in üstüne eklediği, capabilities negotiation arkasında
opsiyonel özellikler. Eski Quick Share peer'ları (Google/Samsung Android, NearDrop) bu
özellikleri görmezden gelir; fallback davranışı her spec'te tanımlıdır.

| # | Doküman | Durum | Eklendi |
|---|---|---|---|
| 001 | [capabilities.md](capabilities.md) | 📝 Draft (RFC-0003 §3.2 byte-exact) | v0.8.0 |
| 002 | [chunk-hmac.md](chunk-hmac.md) | 📝 Draft (RFC-0003 byte-exact) | v0.8.0 |
| 003 | [resume.md](resume.md) | 📝 Draft (RFC-0004 byte-exact) | v0.8.0 |
| 004 | [folder-payload.md](folder-payload.md) | 📝 Draft (RFC-0005 byte-exact, `HEKABUND` v1) | v0.8.0 |

Her spec:
- Byte-level wire layout (alan uzunlukları, encoding)
- State machine (sender/receiver arrow diagram)
- Capabilities gate (hangi bit, fallback davranışı)
- Error handling (mismatch, timeout, abort)
- Example traffic capture (opsiyonel ama önerilir)

## Versiyonlama

Wire format değişiklikleri **semver-benzeri** izlenir ancak protokol için:
- **MAJOR**: geriye uyumsuz, capabilities negotiation ile gate edilmeden yollanamaz
- **MINOR**: geriye uyumlu, yeni opsiyonel alan veya davranış
- **PATCH**: spec netleştirmesi (wire değişmiyor)

Her spec dosyasının başında `Protokol sürümü:` alanı bulunur.

## Test capture'ları

`docs/protocol/captures/` altına (git-tracked) örnek trafik capture'ları:
- Android → HekaDrop file transfer (hex dump)
- HekaDrop → Android URL send
- Resume handshake
- Folder payload roundtrip

Format: `{senaryo}.pcap` ve insan-okunaklı `{senaryo}.md` açıklama.
Fuzz corpus'u buradan türetilebilir.

## Related
- [../rfcs/](../rfcs/) — protocol-shaping tasarım kararları
- [../security/threat-model.md](../security/threat-model.md) — STRIDE per component
- [../../proto/](../../proto/) — Quick Share protobuf şemaları (upstream)
