# HekaDrop Architecture (v0.8.0)

> RFC-0001 Foundation refactor tamamlandı (Adım 1-8). v1.0.0'a kadar **public API stable değil** — her crate `publish = false`.

## Workspace (5 crate)

```
hekadrop-proto    — prost-üretilmiş wire format tipleri (leaf)
       ↑
hekadrop-core     — protokol engine: UKEY2, AES-256-CBC, HMAC, frame,
                    payload, chunk-HMAC (RFC-0003), resume (RFC-0004),
                    folder (RFC-0005), connection, sender, server
       ↑
hekadrop-net      — mDNS discovery + advertising
       ↑
hekadrop-cli      — headless CLI stub (v0.10.0'da gelişecek)
       ↑
hekadrop-app      — binary + UI (tao/wry/tray-icon) + platform shims
                    + i18n + state singleton
```

`hekadrop-app` `pub use hekadrop_core::*` shim ile core sembollerini re-export eder.

## Temel Bağımlılık Akışı

- `core` → `proto` (prost tipleri)
- `net` → `core` (DiscoveredDevice gibi domain tipleri)
- `app` → `core` + `net` + `proto`
- `cli` → `core` + `net`

## Protokol Katmanı (core içinde)

```
TCP accept (server.rs)
  → ConnectionRequest + UKEY2 handshake (ukey2.rs)
  → Capabilities exchange (capabilities.rs + negotiation.rs)
  → Secure channel (secure.rs: AES-256-CBC + HMAC-SHA256)
  → HekaDropFrame / OfflineFrame dispatch (frame.rs)
  → Payload assembly (payload.rs)
      ↳ chunk-HMAC verify (chunk_hmac.rs)  [CHUNK_HMAC_V1]
      ↳ resume sidecar (resume.rs)          [RESUME_V1]
      ↳ folder bundle extract (folder/)     [FOLDER_STREAM_V1]
```

## Extension Noktaları

| Trait | İmplementasyon | Amaç |
|---|---|---|
| `UiPort` | `UiAdapter` (app) | UI bildirimleri (core→UI) |
| `PlatformOps` | `PlatformAdapter` (app) | open_url, clipboard |

Her ikisi de core'un app-specific koda bağımlı olmasını engeller (CLAUDE.md I-1).

## Runtime

- Tokio multi-thread (`rt-multi-thread`)
- UI: `tao` event loop + `wry` WebView (HTML/CSS/JS)
- Tray: `tray-icon`
- Protobuf: `prost` (build.rs'de üretilmiş)

## İlgili Dökümanlar

- Protokol uzantıları: `docs/protocol/`
- RFC'ler: `docs/rfcs/`
- Güvenlik: `docs/security/`
- Bağımlılık politikası: `docs/dependency-policy.md`
