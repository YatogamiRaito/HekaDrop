//! Platform-bound config dosya yolları.
//!
//! RFC-0001 §5 Adım 4 — `identity_path`, `stats_path`, `config_path` core'dan
//! buraya çıkarıldı; core artık `crate::platform::*` çağırmıyor (R2
//! mitigation). Caller bu helper'lardan yolu alıp core API'lerine inject eder.

use std::path::PathBuf;

pub(crate) fn identity_path() -> PathBuf {
    crate::platform::config_dir().join("identity.key")
}

pub(crate) fn stats_path() -> PathBuf {
    crate::platform::config_dir().join("stats.json")
}

pub fn config_path() -> PathBuf {
    crate::platform::config_dir().join("config.json")
}
