//! RFC-0005 — `folder_stream_v1` payload primitives.
//!
//! Bu modül stateless `HEKABUND` v1 wire-byte container ile in-bundle JSON
//! manifest helper'larını barındırır. Sender (PR-C) ve receiver (PR-D) bunu
//! ortak primitive seti olarak tüketir; modül kendisi UI/global state taşımaz.
//!
//! - [`bundle`] — `HEKABUND` header + streaming writer / reader, trailer SHA-256
//! - [`manifest`] — `BundleManifest` JSON schema serde + validate guards
//! - [`sanitize`] — per-segment path traversal + depth/null-byte/separator
//!   guard; `..` reject (`docs/protocol/folder-payload.md` §5)
//!
//! Wire-byte-exact spec: `docs/protocol/folder-payload.md`
//! Normative RFC: `docs/rfcs/0005-folder-payload.md`
//! Capabilities gate: `crate::capabilities::features::FOLDER_STREAM_V1`
//! (PR-D'de proto sırası kilitlenecek).

pub mod bundle;
pub mod enumerate;
pub mod manifest;
pub mod sanitize;

pub use bundle::{
    BundleError, BundleHeader, BundleReader, BundleWriter, HEADER_LEN, HEKABUND_MAGIC,
    HEKABUND_VERSION, MAX_MANIFEST_LEN, TRAILER_LEN,
};
pub use enumerate::{
    build_manifest, bundle_total_size, enumerate_folder, BuildError, EntryKind, EnumerateError,
    EnumeratedEntry, MAX_FOLDER_DEPTH, MAX_FOLDER_ENTRIES,
};
pub use manifest::{BundleManifest, ManifestEntry, ManifestError, MANIFEST_VERSION, MAX_ENTRIES};
pub use sanitize::{sanitize_received_relative_path, sanitize_root_name, PathError, MAX_DEPTH};
