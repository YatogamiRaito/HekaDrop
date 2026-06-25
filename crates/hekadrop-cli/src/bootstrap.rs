//! `AppState` bootstrapping for `hekadrop-cli`.
//!
//! Handles loading settings, backing up corrupted config files, resolving paths,
//! pruning expired trust records, and constructing a clean `Arc<AppState>` instance
//! without resorting to hidden process-level global singletons.

use crate::paths;
use hekadrop_core::settings::Settings;
use hekadrop_core::state::AppState;
use std::path::PathBuf;
use std::sync::Arc;

/// Config dizinine yazma izni olup olmadığını kontrol eder.
///
/// Dizin yoksa oluşturmayı dener; ardından geçici bir dosya ile
/// yazma testi yapar. `/etc` gibi read-only dizinlerde `false` döner.
fn is_dir_writable(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".hekadrop_write_probe");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Bootstraps and returns a clean `Arc<AppState>` instance for the CLI.
///
/// Resolves the unified config, identity, and stats paths, loads settings (with automatic
/// corrupt-file backup fallback), constructs the core `AppState`, and sweeps expired
/// trust keys.
///
/// # Errors
///
/// Returns an error if the configuration directories cannot be created.
#[expect(
    clippy::print_stderr,
    reason = "API: CLI bootstrap logs config loading warning directly to stderr"
)]
pub(crate) fn bootstrap(custom_config_path: Option<PathBuf>) -> anyhow::Result<Arc<AppState>> {
    let is_custom_config = custom_config_path.is_some();

    let (config_p, identity_p, stats_p) = if let Some(custom_path) = custom_config_path {
        let parent = custom_path.parent().map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
        // Güvenlik: --config ile belirtilen dizine yazma izni yoksa (ör. /etc)
        // identity.key ve stats.json gibi state dosyalarını varsayılan kullanıcı
        // dizinlerine yönlendir. Böylece read-only config dizini + yazılabilir
        // state dizini birlikte çalışabilir.
        let (id_p, st_p) = if is_dir_writable(&parent) {
            (parent.join("identity.key"), parent.join("stats.json"))
        } else {
            tracing::warn!(
                "Config dizini ({}) yazılamıyor — identity ve stats varsayılan \
                 kullanıcı dizininde saklanacak",
                parent.display()
            );
            (paths::identity_path(), paths::stats_path())
        };
        (custom_path, id_p, st_p)
    } else {
        (
            paths::config_path(),
            paths::identity_path(),
            paths::stats_path(),
        )
    };
    let dev_name = paths::device_name();
    let download_d = paths::default_download_dir();

    // Ensure config directory exists
    if let Some(parent) = config_p.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Load settings or fallback
    let (settings, settings_err) = Settings::load_or_default(&config_p);
    if let Some(err) = settings_err {
        // Fail-hard: kullanıcı açıkça --config ile bir dosya belirttiyse ve
        // dosya bozuksa, sessizce varsayılanlara dönmek yerine hata ver.
        // Kullanıcı bozuk config'le çalıştığının farkında olmalı.
        if is_custom_config && matches!(err, hekadrop_core::settings::LoadError::Corrupt { .. }) {
            anyhow::bail!(
                "--config ile belirtilen yapılandırma dosyası bozuk: {}\nHata: {err}\n\
                 Dosyayı düzeltin, silin veya --config parametresini kaldırın.",
                config_p.display()
            );
        }

        eprintln!("[HekaDrop] Config load warning: {err}");

        // Backup corrupt file if applicable (only for default config path)
        if matches!(err, hekadrop_core::settings::LoadError::Corrupt { .. }) {
            match hekadrop_core::settings::backup_corrupt_file(&config_p) {
                Ok(backup) => {
                    eprintln!(
                        "[HekaDrop] Corrupt config.json backed up to {} - continuing with defaults.",
                        backup.display()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[HekaDrop] WARNING: Corrupt config.json could not be backed up ({e}) - continuing with defaults."
                    );
                }
            }
        }
    }

    // Construct AppState
    let state = AppState::new(
        settings,
        &identity_p,
        config_p,
        stats_p,
        dev_name,
        download_d,
    );

    // Issue #17: startup'ta süresi dolmuş trust kayıtlarını temizle
    let pruned = state.settings.write().prune_expired();
    if pruned > 0 {
        tracing::info!("Pruned {} expired trust entries", pruned);
    }

    Ok(state)
}
