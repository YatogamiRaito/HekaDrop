# HekaDrop Protocol — Chunk-Level HMAC (wire-level spec)

- **Protocol family:** HekaDrop extensions to Google Quick Share wire format
- **Version:** `chunk_hmac_v1` (capabilities bit `0x0001`)
- **Status:** Draft, hedef implementation v0.8.0
- **Normative RFC:** [`docs/rfcs/0003-chunk-hmac.md`](../rfcs/0003-chunk-hmac.md)
- **Related:** [`capabilities.md`](capabilities.md) — `HekaDropFrame` envelope and
  capability negotiation; [`resume.md`](resume.md) — RFC-0004 reuses the
  per-chunk HMAC tag for fast-path resume verification.
- **Audience:** protocol implementers (Android router authors, 3rd party Quick
  Share clients, fuzz harness writers, audit vendors)

This document is the **byte-exact reference** for HekaDrop's chunk integrity
extension. The prose, motivation, and design trade-offs live in RFC 0003. If
the two documents disagree, the RFC is authoritative for design intent and
this document is authoritative for bytes on the wire.

---

## 1. Why this exists (one paragraph)

Quick Share's existing `SecureCtx` (AES-256-CBC + HMAC-SHA256 over each frame)
already protects against wire tampering — frame-level integrity is solved.
This extension adds a **separate per-chunk HMAC tag** for three reasons that
frame-level integrity does not address:

1. **Resume preconditions** (RFC-0004 §3.4): a receiver that has a partial
   file on disk needs an O(1) way to prove "I have bytes [0..N]" so the sender
   can resume from offset N without a full-file hash recompute.
2. **Storage corruption early-abort:** between `frame::read_frame` (verified
   on the wire) and disk flush, a chunk's plaintext body may be mutated by a
   compromised filesystem layer or hostile process with file-write
   capability. Per-chunk HMAC catches this on the next chunk's tag verify.
3. **Partial integrity as a first-class primitive:** RFC-0005 (folder
   payload) reuses chunk tags so a folder's per-file resume / mid-bundle
   abort can prove which bytes are intact.

**This extension does not duplicate frame-level HMAC.** Wire transit is
already authenticated by `SecureCtx` — chunk-HMAC operates over plaintext
bodies after `SecureCtx::decrypt` succeeds, providing *defense-in-depth* at a
different trust boundary (in-memory plaintext → disk).

---

## 2. Frame placement in the session state machine

```
sender                                 receiver
------                                 --------
  |                                       |
  |  (UKEY2 + Capabilities exchange       |
  |   per docs/protocol/capabilities.md)  |
  |======================================>|
  |                                       |
  |  --- if active_caps & CHUNK_HMAC_V1 ---
  |                                       |
  |  PayloadTransferFrame{                |
  |    payload_header.id = pid,           |
  |    chunk.offset = O,                  |
  |    chunk.body = plaintext bytes       |
  |  }   (encrypted by SecureCtx)         |
  |-------------------------------------->|
  |                                       |
  |  HekaDropFrame{                       |
  |    chunk_tag = ChunkIntegrity{...}    |
  |  }   (encrypted by SecureCtx;         |
  |       same secure stream, next       |
  |       sequence number)                |
  |-------------------------------------->|
  |                                       |   (receiver:
  |                                       |     1. ingest body bytes
  |                                       |     2. wait for ChunkIntegrity
  |                                       |     3. compute expected tag
  |                                       |     4. constant-time compare
  |                                       |     5. on mismatch → abort + cleanup)
  |  ... next chunk + tag ...             |
  |                                       |
  |  --- if active_caps lacks CHUNK_HMAC_V1 ---
  |                                       |
  |  PayloadTransferFrame{...}            |   (legacy; receiver verifies only
  |-------------------------------------->|    end-to-end SHA-256 on last chunk)
  |  ...                                  |
```

**Ordering invariant (normative):**

1. The `PayloadTransferFrame` carrying chunk N's body MUST be sent first.
2. The `HekaDropFrame{chunk_tag = ChunkIntegrity{chunk_index=N, ...}}` MUST
   immediately follow, before any chunk N+1 body or any other Quick Share
   frame.
3. Receivers that observe an out-of-order pair (e.g. body N, body N+1, tag N)
   MUST treat this as a protocol violation, abort the transfer, and remove
   the `.part` file.

**Two `SecureCtx` sequence numbers are consumed per chunk** (one for the body
frame, one for the tag frame). This is acceptable: `SecureCtx` uses a 64-bit
sequence space.

---

## 3. `ChunkIntegrity` message — wire layout

The `HekaDropFrame` envelope (raw 4-byte big-endian magic `0xA5DEB201`, then
protobuf payload) is documented in
[`docs/protocol/capabilities.md`](capabilities.md). This document describes
only the **inner** `ChunkIntegrity` message — the value of
`HekaDropFrame.payload.chunk_tag` (oneof slot 11).

```protobuf
syntax = "proto3";
package hekadrop.ext;

message ChunkIntegrity {
  int64  payload_id  = 1;   // PayloadHeader.id mirror
  int64  chunk_index = 2;   // 0-based monotonic per-payload counter
  int64  offset      = 3;   // PayloadChunk.offset mirror
  uint32 body_len    = 4;   // SHOULD equal len(body) of the matching chunk
  bytes  tag         = 5;   // HMAC-SHA256 = 32 bytes; other lengths reject
}
```

### 3.1 Byte-level encoding (after protobuf serialization)

For a typical chunk with `payload_id = 0x12345678`, `chunk_index = 3`,
`offset = 0x180000` (1.5 MiB), `body_len = 524288` (512 KiB), and a 32-byte
tag, the encoded bytes are approximately:

```
field=1 (payload_id):    08 F8 AC D1 91 01            (varint)
field=2 (chunk_index):   10 03                         (varint)
field=3 (offset):        18 80 80 60                   (varint)
field=4 (body_len):      20 80 80 20                   (varint)
field=5 (tag):           2A 20 <32-bytes-of-tag>       (length-delimited)
```

Total inner protobuf size: **~46-50 bytes** (varint widths vary). Wrapped in
`HekaDropFrame` (4-byte magic + version varint + oneof tag), the on-wire
ChunkIntegrity frame is **~55-60 bytes** before SecureCtx encryption.

### 3.2 Field semantics (normative)

| Field | Type | Constraint | Action on violation |
|---|---|---|---|
| `payload_id` | int64 | MUST equal the `PayloadHeader.id` of the immediately preceding `PayloadTransferFrame` | Abort transfer, remove `.part` |
| `chunk_index` | int64 | MUST be `0` for the first chunk of `payload_id`, and exactly `prev_index + 1` thereafter | Abort transfer |
| `offset` | int64 | MUST equal `PayloadChunk.offset` of the matching chunk | Abort transfer |
| `body_len` | uint32 | MUST equal `len(PayloadChunk.body)` of the matching chunk; bounded above by `2^31 - 1` (i32 ceiling for safety) | Abort transfer |
| `tag` | bytes | MUST be exactly **32 bytes**; other lengths reject without HMAC verify | Abort transfer |

The redundant duplication of `payload_id`, `chunk_index`, and `offset` is
intentional: the tag binds these values, so any rebinding attempt by an
intermediate (post-`SecureCtx` plaintext-tampering scenario) flips the
verification.

---

## 4. Tag derivation — HMAC key and input

### 4.1 Key derivation (HKDF)

The chunk-HMAC key is **separate from** the existing UKEY2 frame-level
HMAC key. Both share the same UKEY2 `next_secret` IKM but use distinct HKDF
labels for domain separation.

```
ikm   = ukey2_handshake.next_secret              (32 bytes)
salt  = empty                                    (zero-length salt)
info  = b"hekadrop chunk-hmac v1"
length = 32

chunk_hmac_key = HKDF-SHA256(ikm, salt, info, length)
```

**Implementation reference** (Rust pseudocode):

```rust
use hekadrop_core::crypto::hkdf_sha256;

let chunk_hmac_key: [u8; 32] = {
    let mut out = [0u8; 32];
    let derived = hkdf_sha256(
        &keys.next_secret,         // UKEY2 IKM
        &[],                       // empty salt
        b"hekadrop chunk-hmac v1", // domain-separated label
        32,
    );
    out.copy_from_slice(&derived);
    out
};
```

The label `"hekadrop chunk-hmac v1"` is fixed; do not change without bumping
to `chunk_hmac_v2` (new capability bit).

### 4.2 HMAC input (canonical encoding)

The MAC input is a fixed-layout concatenation of the chunk's wire identifiers
followed by the plaintext body:

```
hmac_input =
    payload_id_be_i64        ‖     // 8 bytes, big-endian
    chunk_index_be_i64       ‖     // 8 bytes, big-endian
    offset_be_i64            ‖     // 8 bytes, big-endian
    body_len_be_u32          ‖     // 4 bytes, big-endian
    body                            // body_len bytes
```

Total prefix: **28 bytes** before body.

```
tag = HMAC-SHA256(chunk_hmac_key, hmac_input)
    = 32 bytes
```

**Why big-endian?** All four scalar fields use big-endian for cross-platform
byte ordering reproducibility (debug logs, hex dumps, fuzz corpora). HMAC
itself is byte-order-agnostic, but the protocol fixes one order so two
implementations always produce identical inputs.

**Why include redundant `body_len`** when the protobuf field already carries
it? The protobuf field is *outside* the tag's protection. If a tampering
hostile post-`SecureCtx` layer changes `ChunkIntegrity.body_len`, the
receiver-computed `body_len` from the actual body length still matches, and
the redundant fields plus tag verify catches the mismatch.

---

## 5. Tag verification (receiver-side)

```rust
// Pseudocode; production lives in hekadrop-core::secure post-Adım 8.
fn verify_chunk_integrity(
    expected: &ChunkIntegrity,
    body: &[u8],
    chunk_hmac_key: &[u8; 32],
) -> Result<(), Error> {
    // Step 1: length check FIRST (cheap, constant-time-irrelevant).
    if expected.tag.len() != 32 {
        return Err(Error::ProtocolViolation("ChunkIntegrity.tag != 32 bytes"));
    }

    // Step 2: redundant-field consistency (cheap, attacker-known anyway).
    if expected.body_len as usize != body.len() {
        return Err(Error::ProtocolViolation("body_len mismatch"));
    }

    // Step 3: compute expected tag.
    let mut input = Vec::with_capacity(28 + body.len());
    input.extend_from_slice(&expected.payload_id.to_be_bytes());
    input.extend_from_slice(&expected.chunk_index.to_be_bytes());
    input.extend_from_slice(&expected.offset.to_be_bytes());
    input.extend_from_slice(&expected.body_len.to_be_bytes());
    input.extend_from_slice(body);

    let computed = hmac_sha256(chunk_hmac_key, &input);

    // Step 4: constant-time compare.
    use subtle::ConstantTimeEq;
    if computed.ct_eq(&expected.tag).into() {
        Ok(())
    } else {
        Err(Error::IntegrityFailure)
    }
}
```

**The 32-byte length check (Step 1) MUST happen before the constant-time
compare.** Non-constant length check does not open a timing side-channel
because the tag length is attacker-controlled (they sent it) and reveals
nothing about the secret key.

**On failure (any of the 4 steps return Err):**

1. Receiver sends a `Disconnection` frame (Quick Share standard error path).
2. Receiver removes the `.part` file and any `.meta` files
   (per [`docs/protocol/resume.md`](resume.md) §6).
3. Receiver logs the failure with chunk-level granularity (`payload_id`,
   `chunk_index`, body_len, but **never** the body content or expected tag).
4. Sender, on detecting the disconnect, SHOULD attempt one reconnect with
   `offset = 0` (no resume) since the partial state is now untrusted.

---

## 6. Capabilities negotiation reference

`chunk_hmac_v1` is gated by `Capabilities.features` bit `0x0001`. The full
negotiation flow (timing, default fallback, mismatch handling) is documented
in [`docs/protocol/capabilities.md`](capabilities.md). Summary:

- Both peers send `Capabilities{version=1, features=...}` after
  `PairedKeyEncryption`.
- `active_caps = my_features & peer_features`.
- If `active_caps & CHUNK_HMAC_V1 == 0`, this extension is **silent** —
  sender does not emit `ChunkIntegrity` frames, receiver does not expect
  them, end-to-end SHA-256 (legacy) is the only integrity check.
- Mismatched expectation (sender omits when receiver expects, or vice versa)
  is a protocol violation; receiver MUST abort.

---

## 7. Test vectors (KAT)

The implementation MUST pass these known-answer tests. Vectors are derived
from a reference Python port of the algorithm (independent of the Rust
implementation, to catch regressions where "wrong is wrong consistently").

### KAT-1 — Empty body, all-zero key

```
chunk_hmac_key  = 00 00 00 00 ... 00     (32 bytes of 0x00)
payload_id      = 0
chunk_index     = 0
offset          = 0
body_len        = 0
body            = (empty)

hmac_input      = 00 00 00 00 00 00 00 00     (payload_id BE i64)
                  00 00 00 00 00 00 00 00     (chunk_index BE i64)
                  00 00 00 00 00 00 00 00     (offset BE i64)
                  00 00 00 00                 (body_len BE u32)
                                              (body, empty)

tag             = HMAC-SHA256(0x00*32, hmac_input)
                = b613679a 0814d9ec 772f95d7 78c35fc5
                  ff1697c4 93715653 c6c712 14429192
                  ↑ Note: this exact value pending verification with the
                    reference impl during v0.8 implementation phase. Treat
                    as placeholder until KAT-1 is signed off in
                    docs/protocol/captures/chunk-hmac-kat-1.txt.
```

### KAT-2 — Single chunk full body, deterministic key

```
chunk_hmac_key  = HKDF-SHA256(ikm=0x42*32, salt=[], info="hekadrop chunk-hmac v1", L=32)
payload_id      = 0x12345678
chunk_index     = 0
offset          = 0
body_len        = 32
body            = 41 41 ... 41     (32 bytes of 0x41 'A')

hmac_input      = 00 00 00 00 12 34 56 78
                  00 00 00 00 00 00 00 00
                  00 00 00 00 00 00 00 00
                  00 00 00 20
                  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41

tag             = (computed; written to docs/protocol/captures/chunk-hmac-kat-2.txt
                   during implementation; binds the spec to the wire format)
```

The full KAT corpus lives at `docs/protocol/captures/chunk-hmac-kat-*.txt`
and is shared with `fuzz_chunk_hmac_verify` as a golden seed.

---

## 8. Implementation timing budget

For a 1 GiB file at 1 Gbps LAN throughput (~125 MiB/s), with 512 KiB chunks
(2,048 chunks total):

- HMAC compute per chunk: **~1.3 ms** on Apple M1 (SHA-256 ~400 MB/s
  software) or **~0.16 ms** with SHA-NI on x86_64 (≥3 GB/s).
- Per-chunk overhead: **~0.5%** of throughput on M1, **~0.06%** on SHA-NI.
- Worst-case (HDD-bound, software SHA-256, 100 Mbps LAN): **~5%** throughput
  reduction.

**32-byte tag overhead** is `32 / 524288 ≈ 0.006%` of the chunk body —
bandwidth-imperceptible.

The receiver's per-chunk verify is in the hot path (every body buffer must
be MAC-verified before disk write). The sender's per-chunk compute can run
concurrently with the next chunk's read.

---

## 9. Failure modes & recovery

| Trigger | Receiver action | Sender action | Resume behavior |
|---|---|---|---|
| `ChunkIntegrity.tag != 32 bytes` | Abort, remove `.part`/`.meta`, send Disconnection | Reconnect with `offset = 0` | None |
| `body_len` mismatch | Abort, remove `.part`/`.meta`, send Disconnection | Reconnect with `offset = 0` | None |
| Tag verify fails (constant-time `ct_eq` returns false) | Abort, remove `.part`/`.meta`, send Disconnection, log `IntegrityFailure` (no body, no tag) | Reconnect with `offset = 0`; user notified of "transfer corrupted" | None — partial state untrusted |
| Out-of-order: chunk N+1 body before chunk N tag | Abort, treat as protocol violation | Sender bug — should not happen | None |
| Receiver expects tag (capability set) but sender omits | Abort after a 5 second post-body grace period | Sender bug or downgrade attack | None |
| Sender sends tag but receiver lacks capability | Receiver receives an unexpected `HekaDropFrame` and ignores it (frame routing layer); transfer continues without chunk-HMAC verify | Sender bug — should not have negotiated `CHUNK_HMAC_V1` | N/A |

---

## 10. Privacy & logging

The `tag` value MUST NOT be logged at any verbosity. The `body_len`,
`chunk_index`, and `offset` are non-sensitive metadata and MAY be logged at
`info` or `debug` level. The body itself MUST NEVER be logged regardless
of verify outcome.

`payload_id` is a 63-bit random value (top bit cleared); logging it is
acceptable for transfer correlation but provides no information about file
content.

---

## 11. Open questions (tracked in RFC-0003 §10)

1. **Should `ChunkIntegrity` carry a body SHA-256 in addition to HMAC?**
   *Current decision:* No — adds 32 bytes per chunk for a property the HMAC
   already provides under the secret-key threat model. SHA-256 would only
   add value against a key-compromise scenario, which is out of scope.
2. **Should the tag be transmitted alongside the chunk body in a single
   `PayloadTransferFrame` extension field?** *Current decision:* No — would
   require modifying upstream `PayloadHeader`, which is forbidden by the
   "no upstream wire format changes" RFC-0003 rule. Two-frame approach
   accepts the extra `SecureCtx` sequence number cost.
3. **What is the canonical KAT-1 tag value?** *Pending* until reference
   Python implementation is committed to `docs/protocol/captures/`.

---

## 12. References

- [`docs/rfcs/0003-chunk-hmac.md`](../rfcs/0003-chunk-hmac.md) — normative RFC
- [`docs/protocol/capabilities.md`](capabilities.md) — `HekaDropFrame` envelope, capability negotiation
- [`docs/protocol/resume.md`](resume.md) — RFC-0004 spec; reuses chunk tags for fast-path resume
- [`docs/security/threat-model.md`](../security/threat-model.md) — STRIDE; chunk-HMAC closes T-3 (mid-transit body tampering at trust boundary B-2)
- RFC 2104 — HMAC keyed-hashing
- RFC 5869 — HKDF
- FIPS 198-1 — HMAC standard
- FIPS 180-4 — SHA-256
