# HekaDrop Protocol — Transfer Resume (wire-level spec)

- **Protocol family:** HekaDrop extensions to Google Quick Share wire format
- **Version:** `resume_v1` (capabilities bit `0x0002`)
- **Status:** Draft, hedef implementation v0.8.0
- **Normative RFC:** `docs/rfcs/0004-transfer-resume.md`
- **Dependencies:** RFC 0003 (chunk-HMAC) for `last_chunk_tag` field
- **Audience:** protocol implementers (Android router authors, 3rd party
  Quick Share clients, fuzz harness writers)

This document is the **byte-exact reference**. The prose, motivation and
design trade-offs live in RFC 0004. If the two documents disagree, the RFC
is authoritative for design intent and this document is authoritative for
bytes on the wire.

---

## 1. Frame placement in the session state machine

```
sender                                 receiver
------                                 --------
  |                                       |
  |  (UKEY2 + AES-CBC+HMAC secure ch.)    |
  |======================================>|
  |                                       |
  |  V1Frame{type=Introduction,           |
  |          payload_ids=[p1, p2, ...]}   |
  |-------------------------------------->|
  |                                       |
  |       (receiver scans ~/.hekadrop/    |
  |        partial/ for matching          |
  |        session_id + payload_id)       |
  |                                       |
  |  HekaDropFrame{resume_hint=...}       |
  |<--------------------------------------|   (optional; only if partial exists
  |                                       |    AND capabilities.RESUME_V1 set)
  |                                       |
  |  (sender opens local file, seeks to   |
  |   offset, streams SHA-256 [0..offset],|
  |   constant-time compares to hint.hash)|
  |                                       |
  |  -- match --                          |
  |  V1Frame{type=PayloadTransfer,        |
  |          chunk.offset=N, body=...}    |
  |-------------------------------------->|
  |  ... resume from offset ...           |
  |                                       |
  |  -- mismatch --                       |
  |  HekaDropFrame{resume_reject=...,     |
  |               reason=HASH_MISMATCH}   |
  |-------------------------------------->|
  |                                       |   (receiver deletes .part + .meta,
  |                                       |    resets state, expects offset=0)
  |  V1Frame{type=PayloadTransfer,        |
  |          chunk.offset=0, body=...}    |
  |-------------------------------------->|
  |  ... normal restart ...               |
```

**Timing constraints:**

- Receiver MUST send `ResumeHint` within **2000 ms** of receiving the
  matching Introduction frame, or sender falls back to `offset = 0`.
- Sender MUST respond within **30 s** of receiving `ResumeHint` for a
  10 GiB file (SHA-256 verification budget). Larger files scale linearly
  (~5 s/GiB, defansive upper bound for non-SHA-NI CPUs with HDD I/O).
  If receiver does not see a PayloadTransfer or ResumeReject within
  `(30 s + file_size_gib * 5 s)`, it MUST close the connection and
  purge `.part`/`.meta`. (See §11 open-question on adaptive timeout.)

## 2. Frame routing — HekaDropFrame wrapper, **not** `V1Frame.FrameType`

**Kritik:** `ResumeHint` and `ResumeReject` are **not** slots in upstream
`V1Frame.FrameType`. That enum belongs to Google's Quick Share / Nearby
Connections spec (`proto/offline_wire_formats.proto:47`); its defined
values are immutable for third-party implementations. Notably **slot 7
is already `PAIRED_KEY_ENCRYPTION`** upstream, so any "ResumeHint = 7"
claim in earlier drafts was incorrect.

HekaDrop extensions live inside a magic-prefixed `HekaDropFrame` wrapper
(defined in RFC-0003 §3.2) which is carried as the plaintext of an
otherwise-normal `SecureCtx::encrypt` payload:

```
frame_header (length-prefix) ─▶ SecureCtx ciphertext ─▶ plaintext =
    0xA5DEB201 (4 B magic) ∥ protobuf(HekaDropFrame)
```

Oneof slot assignments inside `HekaDropFrame.payload` (canonical table
mirrored from RFC-0003):

| Slot | Field           | Defining RFC |
|-----:|-----------------|--------------|
| 10   | `capabilities`  | RFC-0003     |
| 11   | `chunk_tag`     | RFC-0003     |
| 12   | `resume_hint`   | RFC-0004 (this spec) |
| 13   | `resume_reject` | RFC-0004 (this spec) |
| 14   | `folder_mft`    | RFC-0005     |
| 15..63 | reserved      | future v0.x minor additions |

A non-HekaDrop peer receiving this plaintext sees the magic prefix
as an invalid varint tag for `OfflineFrame` and drops the frame. The
capabilities gate (§7) ensures the frame is never transmitted to such
peers in the first place; the magic prefix is a defence-in-depth
fail-loud marker.

## 3. `ResumeHint` message

Defined inside the shared `proto/hekadrop_extensions.proto` file
(package `hekadrop.ext`, same file that hosts `HekaDropFrame` and
`Capabilities`):

```protobuf
message ResumeHint {
  int64  session_id           = 1;  // required, non-zero
  int64  payload_id           = 2;  // required, matches Introduction
  int64  offset               = 3;  // required, 0 < offset < file_size
  bytes  partial_hash         = 4;  // required, exactly 32 bytes (SHA-256)
  uint32 capabilities_version = 5;  // required, equals Capabilities.version
  bytes  last_chunk_tag       = 6;  // optional; 32 bytes if CHUNK_HMAC_V1 set,
                                     // zero-length otherwise
}
```

Wire carriage: `HekaDropFrame{resume_hint = ResumeHint{...}}` (oneof
slot 12), then magic-prefixed and passed to `SecureCtx::encrypt`.

### 3.1 Field semantics

| Field | Type | Size | Notes |
|-------|------|------|-------|
| `session_id` | `int64` | varint (1-10 B) | First 8 bytes of `SHA-256(UKEY2.auth_key)` interpreted as **big-endian i64**. Sender MUST recompute and drop frame on mismatch. |
| `payload_id` | `int64` | varint (1-10 B) | Identical to `Introduction.FileMetadata[*].payload_id`. Sender drops frame if id not announced in this session's Introduction. |
| `offset` | `int64` | varint (1-10 B) | Number of bytes the receiver has on disk. **Invariant:** `0 < offset < file_size`. Exactly 0 is a protocol violation (sender rejects with `ResumeReject{INVALID_OFFSET}`); `offset == file_size` means "already complete, no transfer needed" — sender sends zero PayloadTransfer frames plus final Disconnection. |
| `partial_hash` | `bytes` | fixed 32 B | SHA-256 over receiver's `.part[0..offset]`. Sender verifies in constant time against its own local file hash. |
| `capabilities_version` | `int32` | varint (1-5 B) | Monotonically-increasing version number of the capabilities frame exchanged earlier. Sender rejects with `ResumeReject{VERSION_MISMATCH}` if peer negotiated a different version than this hint claims. |
| `last_chunk_tag` | `bytes` | 0 or 32 B | If `CHUNK_HMAC_V1` capability bit is set, this is the HMAC-SHA256 tag of the **last fully-received chunk** (chunk ending at `offset`). Lets sender skip the O(offset) full SHA-256 and verify only the last-chunk tag — O(1). If bit not set, field is zero-length and sender falls back to full-hash verification. |

### 3.2 Encoding examples

**Example 1: 1 GiB file, 512 MiB received, no chunk-HMAC.**

```
session_id           = 0x4A8F2E31C7D90B54      -> 10-byte varint
payload_id           = 8 442 310 559           -> 5-byte varint
offset               = 536 870 912             -> 5-byte varint
partial_hash         = <32 bytes SHA-256>      -> 2-byte tag + 32 bytes
capabilities_version = 1                       -> 1 byte
last_chunk_tag       = <empty>                 -> tag only (2 bytes) or omitted
```

Resulting protobuf-encoded frame body ≈ 56 bytes.

**Example 2: 10 GiB file, 9.2 GiB received, chunk-HMAC active.**

```
session_id           = 0xA3F1B82E6CD07419      -> 10-byte varint
payload_id           = 5 138 472 819           -> 5-byte varint
offset               = 9 878 030 336           -> 5-byte varint
partial_hash         = <32 bytes>              -> 34 bytes
capabilities_version = 1                       -> 1 byte
last_chunk_tag       = <32 bytes HMAC>         -> 34 bytes
```

Total ≈ 89 bytes. Wrapped in `HekaDropFrame{resume_hint=...}` (oneof
slot 12, magic-prefixed), then encrypted-then-MAC'd per `src/secure.rs`
standard 16 MiB frame cap — well under limit.

## 4. `ResumeReject` message

Defined in the same `proto/hekadrop_extensions.proto` file. Wire carriage:
`HekaDropFrame{resume_reject = ResumeReject{...}}` (oneof slot 13).

```protobuf
message ResumeReject {
  int64 payload_id = 1;  // echo of the rejected hint
  Reason reason    = 2;

  enum Reason {
    REASON_UNSPECIFIED  = 0;
    HASH_MISMATCH       = 1;  // partial_hash does not match local [0..offset]
    INVALID_OFFSET      = 2;  // offset <= 0 or >= file_size
    VERSION_MISMATCH    = 3;  // capabilities_version disagrees
    PAYLOAD_UNKNOWN     = 4;  // payload_id not in Introduction
    SESSION_MISMATCH    = 5;  // session_id does not match sender-computed value
    INTERNAL_ERROR      = 6;  // sender-side I/O or hash failure
  }
}
```

**Receiver handling on `ResumeReject`:**

| Reason | Receiver action |
|--------|-----------------|
| HASH_MISMATCH | Delete `.part` + `.meta`, restart from `offset=0` |
| INVALID_OFFSET | Delete `.part` + `.meta`, restart (likely local disk corruption) |
| VERSION_MISMATCH | Log warn, retry without `ResumeHint` (downgrade to v0.7 behavior) |
| PAYLOAD_UNKNOWN | Delete stale `.meta` (sender no longer plans to send this file) |
| SESSION_MISMATCH | Delete `.meta` (stale session); log warn — possible key rotation |
| INTERNAL_ERROR | Retain `.meta`, retry on next connection |

## 5. Invariants and validation rules

**Sender MUST** (when it receives `ResumeHint`):

1. Reject if `session_id != session_id_i64(self.ukey2.auth_key)` →
   `ResumeReject{SESSION_MISMATCH}`.
2. Reject if `payload_id` not in `self.current_introduction.payload_ids`
   → `ResumeReject{PAYLOAD_UNKNOWN}`.
3. Reject if `offset <= 0 || offset >= file_size`
   → `ResumeReject{INVALID_OFFSET}`.
4. Reject if `partial_hash.len() != 32`
   → drop frame (malformed; do not echo fields).
5. Compute local `[0..offset]` SHA-256; constant-time compare.
6. If `last_chunk_tag` non-empty, verify HMAC of last chunk (RFC-0003)
   before full SHA-256 (O(1) fast path).
7. On success, seek to `offset`, set `PayloadChunk.offset = offset` on first
   transfer frame.

**Receiver MUST** (before sending `ResumeHint`):

1. Verify `.meta.session_id == session_id_i64(self.ukey2.auth_key)`;
   if not, delete and fall through to normal path.
2. Verify `.meta.payload_id` matches one of the Introduction payload_ids;
   else delete and fall through.
3. Verify `.meta.total_size == Introduction.FileMetadata[payload_id].size`;
   else delete and fall through (sender has different file, same id).
4. Verify `.meta.updated_at` within TTL (default 7 days); else delete.
5. Re-hash `.part[0..offset]` (fresh, not from cache) to detect disk
   corruption between sessions — sender will catch mismatches, but a
   local re-hash saves a round trip.

**Receiver MUST NOT** send more than one `ResumeHint` per payload per session.

## 6. Error handling matrix

| Event | Sender state | Action |
|-------|-------------|--------|
| `ResumeHint` timeout (2 s) | Waiting | Proceed with `offset=0`, normal flow |
| Malformed `ResumeHint` (parse fail) | Waiting | Ignore, proceed with `offset=0` |
| Invalid field per §5 checks | Waiting | Send `ResumeReject`, proceed with `offset=0` |
| Hash verify success | Waiting | Seek + send PayloadTransfer frames |
| Local file missing (sender path changed) | Waiting | Send `ResumeReject{PAYLOAD_UNKNOWN}` |
| Mid-resume disconnect | Resuming | Same as v0.7: abort; receiver retains `.part`+`.meta` if CHUNK_HMAC valid |
| TTL expiry mid-resume | N/A | Cleanup sweep skips in-use files |
| Budget eviction mid-resume | N/A | Cleanup sweep skips in-use sessions |

## 7. Capabilities negotiation

The capabilities frame is defined by RFC 0003. Resume adds the
`RESUME_V1 = 0x0002` bit. Both peers MUST advertise this bit in the
capabilities exchange for `ResumeHint` to be transmitted. The
`capabilities_version` field in `ResumeHint` MUST equal the version
negotiated at handshake.

**Downgrade behavior:**

- Neither peer advertises bit → no resume. Normal byte-0 transfer.
- Only sender advertises → receiver cannot send hint; sender receives
  no hint; falls through 2 s timeout.
- Only receiver advertises → receiver transmits `HekaDropFrame{resume_hint}`;
  sender does not recognize the `HekaDropFrame` magic prefix (non-HekaDrop
  peer) or does not advertise `RESUME_V1` (HekaDrop peer with the bit off)
  → logs warn, drops frame, proceeds with byte-0 transfer. Receiver
  `.part` is kept and retried on next session.

## 8. `.meta` JSON schema (receiver-local, **not on wire**)

```json
{
  "version": 1,
  "session_id": "<16-char lowercase hex>",
  "payload_id": <int64>,
  "file_name": "<sanitized name from Introduction>",
  "total_size": <int64>,
  "received_bytes": <int64>,
  "chunk_hmac_chain": "<base64(concat of last 4 chunk HMAC tags)>",
  "peer_endpoint_id": "<string from Introduction>",
  "created_at": "<RFC3339 UTC>",
  "updated_at": "<RFC3339 UTC>"
}
```

`version` monotonically increasing; incompatible changes bump this. v0.8
parser rejects `version > 1`.

`session_id` is the hex representation (not the i64 form) for
human-readable filenames. Conversion: `format!("{:016x}", id as u64)`.

## 9. Security considerations (wire-level only)

- `ResumeHint` and `ResumeReject` are carried **inside the UKEY2-derived
  secure channel**. No plaintext exposure on the LAN.
- Replay within a session: receiver must not send duplicate hints; sender
  logs and drops subsequent hints for the same `payload_id`.
- Cross-session replay: impossible because `session_id` is derived from
  this session's `auth_key`, which is ephemeral ECDH material.
- Hash oracle: sender reveals no information on mismatch beyond "hash
  differs"; `partial_hash` is not a pre-image for any long-lived key.

## 10. Interop test vectors

Implementers SHOULD validate against these vectors
(all hex, no separators):

**Vector 1: small file, tiny offset**

- Input file: `000102...FF` (256 bytes repeating), total 1 024 bytes
- Offset: `128`
- SHA-256 of `[0..128]`: `7ca6d9a3e8b2f6...` *(to be finalized in test
  harness — computed at implementation time)*
- Expected `ResumeHint` wire (protobuf):
  `08<session_varint> 10<payload_varint> 1880 01 2220<32 hash bytes> 2801`

**Vector 2: large file, chunk-HMAC tag**

- Input file: 10 GiB of `0x42`
- Offset: `9 878 030 336` (after 18,840 chunks of 512 KiB)
- `last_chunk_tag`: HMAC-SHA256 of chunk #18839 under chunk-HMAC key

Full vectors will be shipped as `tests/resume/vectors.bin` once the
implementation lands (PR accompanying RFC 0004 merge).

---

## 11. Open questions (wire-level)

1. Should `ResumeHint` support **multi-file** resume in a single frame
   (repeated `Hint` sub-message) when Introduction announces multiple
   files? Current design: one hint per payload; simpler, allows per-file
   reject. Alternative adds complexity with unclear upside — deferred.
2. Should `ResumeReject.reason` expose `INTERNAL_ERROR` at all (vs.
   silent drop + timeout on receiver)? Silent drop leaks less info but
   makes debugging harder. Current: explicit reason code, logged on
   receiver with rate-limiting.
3. Chunk-HMAC's exact tag size / algorithm (HMAC-SHA256 vs Poly1305)
   is owned by RFC 0003. This document assumes SHA-256 (32 B tag); if
   RFC 0003 chooses differently, update §3.1 `last_chunk_tag` size.
4. **Adaptive verify-timeout.** §1 specifies a static `30 s + 5 s/GiB`
   budget — defensive for non-SHA-NI CPUs paired with HDDs. A future
   iteration could measure the first chunk's hash throughput and scale
   the budget dynamically (e.g. `30 s + max(3, 10_000 / measured_MiB_s) * file_size_gib`),
   tightening the window for modern hardware while keeping the slow-path
   budget. Tradeoff: more state on sender, more surface for a malicious
   receiver to stall the protocol by triggering a slow first chunk.
   Deferred to v0.9.
