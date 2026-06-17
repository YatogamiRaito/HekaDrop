//! Headless UI and platform adapters for `hekadrop-cli`.
//!
//! Provides the shims for `UiPort` and `PlatformOps` to allow `hekadrop-core` to run
//! in a headless environment. Handles interactive TTY confirmation prompts,
//! automated `--accept` policies, and real-time progress bars / JSON streaming.

use async_trait::async_trait;
use hekadrop_core::connection::PlatformOps;
use hekadrop_core::state::{AppState, ProgressState};
use hekadrop_core::ui_port::{
    AcceptDecision, FileSummary, FolderPromptSummary, UiNotification, UiPort,
};
use std::io::{stderr, stdin, stdout, IsTerminal, Write};
use std::sync::Arc;
use std::time::Duration;

/// Accept modes supported by the headless CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptMode {
    /// Interactive TTY prompting. Fallback to Reject if no TTY.
    Interactive,
    /// Auto-accept all incoming transfers.
    All,
    /// Auto-accept only verified trusted devices (by hash validation). Reject others.
    Trusted,
}

/// Headless terminal implementation of the `UiPort` trait.
pub(crate) struct CliUiPort {
    accept_mode: AcceptMode,
}

impl CliUiPort {
    /// Creates a new `CliUiPort` with the specified accept mode.
    pub(crate) fn new(accept_mode: AcceptMode) -> Self {
        Self { accept_mode }
    }
}

#[expect(
    clippy::print_stderr,
    reason = "API: CliUiPort prints notifications and prompts to stderr"
)]
#[async_trait]
impl UiPort for CliUiPort {
    fn notify(&self, n: UiNotification) {
        match n {
            UiNotification::Toast {
                title_key,
                body_key,
                body_args,
            } => {
                eprintln!(
                    "📢 [{}] {} {:?}",
                    title_key,
                    body_key.unwrap_or(""),
                    body_args
                );
            }
            UiNotification::FileReceived {
                title_key,
                body_key,
                body_args,
                path,
            } => {
                eprintln!(
                    "✅ [{}] File successfully received: {} (Key: {}, Args: {:?})",
                    title_key,
                    path.display(),
                    body_key,
                    body_args
                );
            }
            UiNotification::FolderReceived {
                title_key,
                body_key,
                body_args,
                path,
            } => {
                eprintln!(
                    "✅ [{}] Folder successfully received: {} (Key: {}, Args: {:?})",
                    title_key,
                    path.display(),
                    body_key,
                    body_args
                );
            }
            UiNotification::ToastRaw { title, body } => {
                eprintln!("📢 [{title}] {body}");
            }
            UiNotification::TrustMigrationHint { device, pin } => {
                eprintln!("⚠️ Legacy trust detected for '{device}'. Migration prompt PIN: {pin}");
            }
        }
    }

    async fn prompt_accept(
        &self,
        device: &str,
        pin: &str,
        files: &[FileSummary],
        text_count: usize,
        folder: Option<&FolderPromptSummary>,
    ) -> AcceptDecision {
        match self.accept_mode {
            AcceptMode::All => {
                eprintln!("⚠️ [Auto-Accept All] Accepting transfer from '{device}' (PIN: {pin})");
                return AcceptDecision::Accept;
            }
            AcceptMode::Trusted => {
                eprintln!("⚠️ [Auto-Accept Trusted] Device '{device}' is not trusted via SHA-256 hash. Rejecting.");
                return AcceptDecision::Reject;
            }
            AcceptMode::Interactive => {}
        }

        // TTY Check
        if !std::io::stdin().is_terminal() {
            eprintln!("⚠️ [No TTY] Headless environment without TTY. Rejecting transfer from '{device}' (PIN: {pin})");
            return AcceptDecision::Reject;
        }

        eprintln!("\n🔔 Incoming HekaDrop request!");
        eprintln!("   From Device:  {device}");
        eprintln!("   One-Time PIN: {pin}");

        if let Some(folder_sum) = folder {
            eprintln!(
                "   Payload:      📁 Folder '{}' containing {} items ({})",
                folder_sum.root_name,
                folder_sum.entry_count,
                format_size(folder_sum.total_size)
            );
        } else {
            eprintln!("   Payload:");
            if text_count > 0 {
                eprintln!("     📝 {text_count} text clip(s)");
            }
            for file in files {
                eprintln!("     📄 {} ({})", file.name, format_size(file.size));
            }
        }

        loop {
            eprint!("👉 Accept transfer? [y/N/t] (y: Yes, n: No, t: Accept & Trust): ");
            let _ = stderr().flush();

            let mut input = String::new();
            if stdin().read_line(&mut input).is_err() {
                return AcceptDecision::Reject;
            }

            match input.trim().to_lowercase().as_str() {
                "y" | "yes" => return AcceptDecision::Accept,
                "n" | "no" | "" => return AcceptDecision::Reject,
                "t" | "trust" => return AcceptDecision::AcceptAndTrust,
                _ => {
                    eprintln!("Invalid option. Please enter 'y', 'n', or 't'.");
                }
            }
        }
    }
}

/// Headless platform operations adapter printing actions to stderr.
pub(crate) struct CliPlatformOps;

#[expect(
    clippy::print_stderr,
    reason = "API: CliPlatformOps prints URLs and clipboard actions to stderr"
)]
impl PlatformOps for CliPlatformOps {
    fn open_url(&self, url: &str) {
        eprintln!("🔗 Open URL requested: {url}");
    }

    fn copy_to_clipboard(&self, text: &str) {
        eprintln!("📋 Copy to clipboard requested: '{text}'");
    }
}

/// Spawns a background task that polls progress from `AppState` and prints updates.
#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "API: start_progress_tracker writes real-time progress to stdout/stderr"
)]
pub(crate) fn start_progress_tracker(
    state: Arc<AppState>,
    json_mode: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_state = ProgressState::Idle;
        let mut last_percent = 0u8;

        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;

            let current_state = state.read_progress();

            if current_state != last_state {
                match &current_state {
                    ProgressState::Idle => {
                        if json_mode {
                            if let Ok(js) =
                                serde_json::to_string(&serde_json::json!({ "status": "idle" }))
                            {
                                println!("{js}");
                                let _ = stdout().flush();
                            }
                        } else if matches!(last_state, ProgressState::Receiving { .. }) {
                            eprintln!("\n💤 Transfer idle.");
                        }
                    }
                    ProgressState::Receiving {
                        device,
                        file,
                        percent,
                    } => {
                        last_percent = *percent;
                        if json_mode {
                            if let Ok(js) = serde_json::to_string(&serde_json::json!({
                                "status": "receiving",
                                "device": device,
                                "file": file,
                                "percent": percent
                            })) {
                                println!("{js}");
                                let _ = stdout().flush();
                            }
                        } else {
                            let bar = render_progress_bar(*percent);
                            eprint!("\r📥 Receiving: {file} from {device} {bar}");
                            let _ = stderr().flush();
                        }
                    }
                    ProgressState::Completed { file } => {
                        if json_mode {
                            if let Ok(js) = serde_json::to_string(&serde_json::json!({
                                "status": "completed",
                                "file": file
                            })) {
                                println!("{js}");
                                let _ = stdout().flush();
                            }
                        } else {
                            eprintln!("\n✅ Transfer of '{file}' completed successfully!");
                        }
                    }
                }
                last_state = current_state;
            } else if let ProgressState::Receiving {
                device,
                file,
                percent,
            } = &current_state
            {
                if *percent != last_percent {
                    last_percent = *percent;
                    if json_mode {
                        if let Ok(js) = serde_json::to_string(&serde_json::json!({
                            "status": "receiving",
                            "device": device,
                            "file": file,
                            "percent": percent
                        })) {
                            println!("{js}");
                            let _ = stdout().flush();
                        }
                    } else {
                        let bar = render_progress_bar(*percent);
                        eprint!("\r📥 Receiving: {file} from {device} {bar}");
                        let _ = stderr().flush();
                    }
                }
            }
        }
    })
}

/// Formats a byte count into a human-readable string.
#[expect(
    clippy::cast_precision_loss,
    reason = "HUMAN: formatting file sizes does not need byte-perfect precision"
)]
fn format_size(bytes: i64) -> String {
    let bytes = bytes as f64;
    if bytes < 1024.0 {
        format!("{bytes:.0} B")
    } else if bytes < 1024.0 * 1024.0 {
        format!("{:.2} KB", bytes / 1024.0)
    } else if bytes < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} MB", bytes / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Renders a beautiful progress bar string.
fn render_progress_bar(percent: u8) -> String {
    let width = 30;
    let filled = ((percent as usize * width) + 50) / 100;
    let empty = width.saturating_sub(filled);

    let bar: String = std::iter::repeat_n("█", filled)
        .chain(std::iter::repeat_n("░", empty))
        .collect();

    format!("[{bar}] {percent}%")
}
