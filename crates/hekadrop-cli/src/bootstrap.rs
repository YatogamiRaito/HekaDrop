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
    let (config_p, identity_p, stats_p) = if let Some(custom_path) = custom_config_path {
        let parent = custom_path.parent().map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
        (
            custom_path,
            parent.join("identity.key"),
            parent.join("stats.json"),
        )
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
        eprintln!("[HekaDrop] Config load warning: {err}");

        // Backup corrupt file if applicable
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
