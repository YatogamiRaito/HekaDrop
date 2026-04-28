# HekaDrop Protocol — `HekaDropFrame` Envelope & Capabilities (wire-level spec)

- **Protocol family:** HekaDrop extensions to Google Quick Share wire format
- **Version:** v1 (envelope), `Capabilities.version = 1`
- **Status:** Draft, hedef implementation v0.8.0
- **Normative RFC:** [`docs/rfcs/0003-chunk-hmac.md`](../rfcs/0003-chunk-hmac.md) §3.2
  (RFC 0003 is the "first mover" — it defines the envelope used by 0004 and
  0005)
- **Audience:** protocol implementers, audit vendors, fuzz harness writers

This document is the **byte-exact reference** for the HekaDrop envelope and
capability negotiation. All HekaDrop protocol extensions (chunk-HMAC,
transfer resume, folder payload, future v0.9+ minor additions) ride inside
this envelope. The prose, motivation, and rejected alternatives live in
RFC 0003. If the two documents disagree, RFC 0003 is authoritative for design
intent and this document is authoritative for bytes on the wire.

---

## 1. Why this exists (one paragraph)

HekaDrop ships protocol extensions that Quick Share peers (Samsung, Pixel,
NearDrop, rquickshare) do not understand. We **MUST NOT** modify upstream
Google `proto/offline_wire_formats.proto` or `proto/sharing.proto`
definitions — adding values to `V1Frame.FrameType` or new oneof slots in
upstream messages would silently break interop or claim slot numbers that
Google later assigns. The solution: a separate envelope frame discriminated
by a 4-byte magic prefix that legacy peers fail to parse and drop, gated
behind opt-in capability negotiation so it is **never** sent to a peer that
hasn't advertised support.

---

## 2. Wire layout — `HekaDropFrame` envelope

HekaDrop frames travel inside the existing Quick Share length-prefixed frame
layer (`[4-byte big-endian length][frame body]`) and inside `SecureCtx`
encryption — they are not visible on the wire as plaintext. The body of
each `SecureCtx`-encrypted frame is structured as:

```
+---------------------+----------------------------------------+
|   magic (4 bytes)   |        HekaDropFrame protobuf          |
|   0xA5 0xDE 0xB2 01 |   (varint-delimited proto3 fields)     |
+---------------------+----------------------------------------+
        ▲                              ▲
        │                              │
        │                              └── decoded only after magic match
        │
        └─── big-endian; protobuf-OUTSIDE; legacy peers fail to parse here
```

### 2.1 Why magic is **outside** protobuf

A previous draft of RFC 0003 declared `fixed32 magic = 1` inside the
`HekaDropFrame` message, but proto3 wire encoding for a `fixed32` field
is `[tag byte 0x0d][4-byte little-endian value]` — the first byte on the
wire is `0x0d`, not `0xA5`. That makes "first 4 bytes are magic" untrue
(and conflicts with the document's "big-endian" claim — proto fixed32 is
LE). Moving the magic outside protobuf:

1. Fixes the byte-order ambiguity (raw network byte order, big-endian
   sentinel).
2. Makes the dispatcher's first decision a 4-byte memcmp, not a protobuf
   parse.
3. Preserves the rule "we never emit `HekaDropFrame` to a peer who hasn't
   advertised the capability" — the magic itself is opt-in, peers without
   capability never see it.

### 2.2 Dispatcher (receiver-side)

```rust
const HEKADROP_MAGIC_BE: &[u8; 4] = &[0xA5, 0xDE, 0xB2, 0x01];

fn dispatch(frame_body: &[u8]) -> Result<Frame, Error> {
    if frame_body.len() >= 4 && &frame_body[..4] == HEKADROP_MAGIC_BE {
        let inner = &frame_body[4..];
        Ok(Frame::HekaDrop(HekaDropFrame::decode(inner)?))
    } else {
        Ok(Frame::Offline(OfflineFrame::decode(frame_body)?))
    }
}
```

A legacy Quick Share peer receiving `0xA5DEB201` interprets it as either a
varint (oversized) or a protobuf field tag with reserved wire type — both
paths produce an `OfflineFrame::decode` error and the frame is dropped
without state change. **However**, capability-gated emission means HekaDrop
peers MUST NOT send these frames to a peer that didn't advertise support;
the magic+drop is a *defense-in-depth* backstop, not the primary
compatibility mechanism.

---

## 3. `HekaDropFrame` and `Capabilities` — protobuf schema

```protobuf
syntax = "proto3";
package hekadrop.ext;

// File: proto/hekadrop_extensions.proto (HekaDrop-only; not in upstream tree)

message HekaDropFrame {
  // NOTE: The 4-byte big-endian magic discriminator (0xA5DEB201) is the
  // raw byte prefix of this message on the wire — NOT a protobuf field.
  // The dispatcher strips it before calling HekaDropFrame::decode.
  uint32 version = 1;  // monotonic; v0.8 = 1
  oneof payload {
    Capabilities    capabilities  = 10;  // RFC 0003 §3.2
    ChunkIntegrity  chunk_tag     = 11;  // RFC 0003 §3.2
    ResumeHint      resume_hint   = 12;  // RFC 0004
    ResumeReject    resume_reject = 13;  // RFC 0004
    FolderManifest  folder_mft    = 14;  // RFC 0005
    // 15..63 — reserved for future v0.x minor additions; SLOTS 1..9
    //         are intentionally left empty for non-payload core fields
    //         (e.g. correlation_id, trace_span) we may add in v0.9+.
  }
}

message Capabilities {
  uint32 version  = 1;  // monotonic; v0.8.0 = 1
  uint64 features = 2;  // bitmask; see §4
}

message ChunkIntegrity {
  // See docs/protocol/chunk-hmac.md for byte-exact spec.
  int64  payload_id  = 1;
  int64  chunk_index = 2;
  int64  offset      = 3;
  uint32 body_len    = 4;
  bytes  tag         = 5;
}

message ResumeHint {
  // See docs/protocol/resume.md for byte-exact spec.
  int64 payload_id    = 1;
  int64 offset        = 2;
  bytes partial_hash  = 3;
  bytes last_chunk_tag = 4;
  uint32 capabilities_version = 5;
}

message ResumeReject {
  enum Reason {
    UNKNOWN          = 0;
    HASH_MISMATCH    = 1;
    TTL_EXPIRED      = 2;
    VERSION_MISMATCH = 3;
    DISK_BUDGET      = 4;
  }
  int64  payload_id = 1;
  Reason reason     = 2;
}

message FolderManifest {
  // See docs/protocol/folder-payload.md (RFC 0005).
  // Field set sealed during v0.8 implementation; this slot reserved.
}
```

### 3.1 Oneof slot policy (normative)

- Slots **1–9 are intentionally empty** in `HekaDropFrame.payload` for
  future *non-payload* additions (correlation IDs, tracing, etc.).
- Slots **10–14 are sealed** to the five extensions above.
- Slots **15–63** are reserved for future v0.x minor additions; new RFCs
  will claim them in numerical order.
- Proto3 `reserved` keyword is **NOT** used inside this oneof — `reserved`
  in a oneof block forbids future use, which is the opposite of what we
  want. Slot management is purely documentary/policy-driven.

---

## 4. Feature bits — `Capabilities.features`

```
bit 0  (0x0000_0001) = CHUNK_HMAC_V1     — RFC 0003 (chunk-HMAC)
bit 1  (0x0000_0002) = RESUME_V1         — RFC 0004 (transfer resume)
bit 2  (0x0000_0004) = FOLDER_STREAM_V1  — RFC 0005 (folder payload)
bit 3..15            — reserved for v0.8–v1.0 extensions
bit 16..63           — reserved for v1.1+ extensions
```

The Rust constants live in `hekadrop-core::capabilities`:

```rust
pub mod features {
    pub const CHUNK_HMAC_V1:    u64 = 0x0000_0001;
    pub const RESUME_V1:        u64 = 0x0000_0002;
    pub const FOLDER_STREAM_V1: u64 = 0x0000_0004;

    /// All features this build supports. Sender advertises this on
    /// `Capabilities.features`; the active set is `my & peer`.
    pub const ALL_SUPPORTED: u64 = CHUNK_HMAC_V1 | RESUME_V1 | FOLDER_STREAM_V1;
}
```

**Adding a new feature bit is a wire-protocol change** — it requires:

1. A new RFC.
2. `Capabilities.version` bump (current = 1).
3. Capabilities-mismatch fallback verified (older peer sees an unknown
   bit and silently ignores it; the active intersection still works).

---

## 5. Negotiation state machine

```
sender                                 receiver
------                                 --------
  |                                       |
  |  ConnectionRequest (Quick Share)      |
  |-------------------------------------->|
  |                                       |
  |  UKEY2 client_init / server_init      |
  |======================================>|
  |  (mutual handshake — both sides       |
  |   compute next_secret + auth_key)     |
  |                                       |
  |  ConnectionResponse Accept            |
  |======================================>|
  |                                       |
  |  PairedKeyEncryption (Quick Share)    |
  |======================================>|
  |                                       |
  |  --- Capabilities exchange ---        |
  |                                       |
  |  HekaDropFrame{capabilities = {       |
  |    version = 1,                       |
  |    features = ALL_SUPPORTED,          |
  |  }}                                   |
  |-------------------------------------->|
  |                                       |
  |  HekaDropFrame{capabilities = {       |
  |    version = 1,                       |
  |    features = peer_supported,         |
  |  }}                                   |
  |<--------------------------------------|
  |                                       |
  |  active_caps = my.features & peer.features
  |                                       |
  |  PairedKeyResult, Introduction, ...   |
  |======================================>|
```

### 5.1 Timing constraints (normative)

- Both sides MUST send their `Capabilities` frame **after**
  `PairedKeyEncryption` and **before** any post-pairing payload frames.
- The receiver MUST send `Capabilities` within **2000 ms** of receiving the
  sender's `Capabilities`. If the sender does not see the peer's
  `Capabilities` within this window, it falls back to **legacy mode**:
  `active_caps = 0` (no extensions; behaves as a vanilla Quick Share peer).
- Legacy fallback is silent — no error to the user; the transfer proceeds
  without chunk-HMAC, resume, or folder support.

### 5.2 Version mismatch handling

If the peer's `Capabilities.version > my.version`, the local side treats
unknown future feature bits as "not supported" and zeros them in
`active_caps`. The version field is **not** used to gate the negotiation
itself — only individual feature bits gate behavior.

If the peer's `Capabilities.version < my.version`, the same logic applies
in reverse (we may know features the peer does not). No downgrade attack
opportunity exists because each bit has independent sender/receiver
preconditions.

### 5.3 Active capability application

After `active_caps` is computed:

| Bit set | Behavior change |
|---|---|
| `CHUNK_HMAC_V1` | Sender emits `ChunkIntegrity` after each `PayloadTransferFrame`; receiver expects and verifies. See [`chunk-hmac.md`](chunk-hmac.md) §2. |
| `RESUME_V1` | Sender includes resume-able payloads in Introduction; receiver may respond with `ResumeHint`. See [`resume.md`](resume.md) §1. |
| `FOLDER_STREAM_V1` | Folder bundles use the `FolderManifest` extension instead of legacy multi-file fallback. See [`folder-payload.md`](folder-payload.md) (TBD v0.8). |

If `active_caps == 0`, no `HekaDropFrame` is ever emitted by either side
for the rest of the session — the wire looks identical to a legacy Quick
Share session.

---

## 6. Failure modes

| Trigger | Effect | Notes |
|---|---|---|
| Magic prefix mismatch (legacy peer receives our frame) | Frame dropped by `OfflineFrame::decode` error | Should never happen — capabilities-gated emission. Defense in depth. |
| `HekaDropFrame::decode` fails after magic match | Receiver sends Disconnection, treats as protocol violation | Indicates a peer/version mismatch bug. |
| `Capabilities` frame arrives twice in one session | Second one ignored, log a warning | Spec-compliant peers send once. |
| `Capabilities` not received within 2000 ms | Sender proceeds in legacy mode (active_caps = 0) | Silent degradation, no error to user. |
| Sender sets `CHUNK_HMAC_V1` in capabilities but does not emit `ChunkIntegrity` | Receiver aborts the transfer after a 5 s grace window | Sender bug or downgrade attack. |

---

## 7. Privacy & logging

- `Capabilities.features` MAY be logged at `info` level — it is a
  fingerprint of build version (~3 bits of entropy in v0.8) and reveals no
  user data.
- `Capabilities.version` is loggable.
- The `HekaDropFrame.payload` oneof discriminator (which extension fired)
  is loggable.
- Inner extension messages (ChunkIntegrity tag, ResumeHint partial_hash,
  FolderManifest entries) follow each extension's own redaction rules
  (see linked specs).

---

## 8. Test vectors (KAT)

### KAT-CAP-1 — Empty capabilities (legacy fallback)

Both sides advertise `features = 0`:

```
HekaDropFrame{
  version: 1
  capabilities: { version: 1, features: 0 }
}
```

Encoded inner bytes (after magic prefix):

```
08 01                       (HekaDropFrame.version = 1)
52 04                       (oneof slot 10 = capabilities, length 4)
   08 01                    (Capabilities.version = 1)
   10 00                    (Capabilities.features = 0)
```

On-wire: `A5 DE B2 01 08 01 52 04 08 01 10 00` — 12 bytes total before
SecureCtx encryption.

### KAT-CAP-2 — All v0.8 features

`features = 0x0007` (CHUNK_HMAC_V1 | RESUME_V1 | FOLDER_STREAM_V1):

```
A5 DE B2 01 08 01 52 04 08 01 10 07
```

Same 12 bytes; only the last byte differs (`0x00` → `0x07`).

The full KAT corpus lives at `docs/protocol/captures/capabilities-kat-*.txt`.

---

## 9. Security considerations

The `Capabilities` exchange happens **inside** the `SecureCtx`-encrypted
channel (after UKEY2 + AES-CBC + HMAC). An on-path adversary cannot:

- See or modify the advertised feature set without breaking AES-CBC + HMAC.
- Trick a peer into a downgrade by stripping `Capabilities` frames — the
  2 s timeout only matters if one peer is malicious *and* on-path; in that
  case the attacker can already drop arbitrary frames, and downgrading to
  legacy mode is no worse than what they could do by dropping the entire
  session.

A **trusted-but-buggy** peer that lies about capabilities (e.g., advertises
`CHUNK_HMAC_V1` but doesn't emit tags) is detected by the protocol-violation
abort path (§6).

The 4-byte magic prefix has no cryptographic meaning — it is purely a
dispatch discriminator. It does not authenticate the frame; that is
`SecureCtx`'s job.

---

## 10. Open questions (tracked in RFC 0003 §10)

1. Should `Capabilities.version` ever be allowed to skip values (e.g., go
   from 1 to 3)? *Current decision:* monotonic; gaps imply version-bump
   bugs. Reserve any "experimental" intermediates inside the same version.
2. Should the magic prefix be configurable for testing (different magic
   per test environment)? *Current decision:* No — single magic, fixed
   forever; testing uses real magic with synthetic peers.

---

## 11. References

- [`docs/rfcs/0003-chunk-hmac.md`](../rfcs/0003-chunk-hmac.md) — normative RFC for envelope and capability negotiation
- [`docs/protocol/chunk-hmac.md`](chunk-hmac.md) — chunk-HMAC byte-exact spec
- [`docs/protocol/resume.md`](resume.md) — resume byte-exact spec
- [`docs/protocol/README.md`](README.md) — protocol doc index
- [`proto/offline_wire_formats.proto`](../../crates/hekadrop-proto/proto/offline_wire_formats.proto) — upstream Quick Share `V1Frame.FrameType` (slot 7 = `PAIRED_KEY_ENCRYPTION` — do not collide!)
- RFC 7159 — JSON (used in `FolderManifest` once v0.8 ships, NOT in this envelope)
