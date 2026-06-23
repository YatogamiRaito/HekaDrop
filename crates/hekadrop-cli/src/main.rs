//! `HekaDrop` CLI — fully functional headless entrypoint supporting mDNS peer discovery,
//! secure file sending/receiving, trust key management, and network diagnostics.
//!
//! // TODO(v0.11): extract shared logic to hekadrop-platform crate.

mod bootstrap;
mod paths;
mod terminal;

use crate::terminal::{AcceptMode, CliPlatformOps, CliUiPort, start_progress_tracker};
use clap::{Parser, Subcommand, ValueEnum};
use hekadrop_core::discovery_types::DiscoveredDevice;
use hekadrop_core::state::AppState;
use std::io::{IsTerminal, Write, stderr, stdin};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "hekadrop-cli",
    version = "0.10.0",
    about = "HekaDrop — Headless CLI Quick Share file sharing tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List discovered `HekaDrop` & Quick Share peers on the local network
    ListPeers {
        /// Duration in seconds to scan the network for peers
        #[arg(long, default_value = "3")]
        scan_secs: u64,

        /// Print peer information in structured JSON format
        #[arg(long)]
        json: bool,
    },
    /// Send files or a directory to a discovered peer
    Send {
        /// Paths to the files or directory to send
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Name or IP address of the target device to skip selection
        #[arg(long)]
        to: Option<String>,

        /// Duration in seconds to scan the network for peers
        #[arg(long, default_value = "3")]
        scan_secs: u64,

        /// Stream progress and state in structured JSON format
        #[arg(long)]
        json: bool,
    },
    /// Send text payload to a discovered peer
    SendText {
        /// The text payload to send
        #[arg(required = true)]
        text: String,

        /// Name or IP address of the target device to skip selection
        #[arg(long)]
        to: Option<String>,

        /// Duration in seconds to scan the network for peers
        #[arg(long, default_value = "3")]
        scan_secs: u64,

        /// Stream progress and state in structured JSON format
        #[arg(long)]
        json: bool,
    },
    /// Listen and receive incoming `HekaDrop` / Quick Share transfers
    Receive {
        /// Accept policy mode: 'interactive' (TTY prompt), 'all' (auto-accept all), 'trusted' (auto-accept trusted only)
        #[arg(long, value_enum, default_value = "interactive")]
        accept: CliAcceptMode,

        /// Stream progress and state in structured JSON format
        #[arg(long)]
        json: bool,
    },
    /// Trust management for trusted devices
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Network diagnostics and system configuration sanity checks
    Doctor,
    /// Print `HekaDrop` CLI and Core version information
    Version,
    /// Run `HekaDrop` as a background system service (launchd/systemd daemon)
    Daemon {
        /// Path to custom config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CliAcceptMode {
    Interactive,
    All,
    Trusted,
}

#[derive(Subcommand)]
enum TrustAction {
    /// List all trusted devices
    List {
        /// Format the list in structured JSON
        #[arg(long)]
        json: bool,
    },
    /// Manually trust a device
    Add {
        /// Device name
        name: String,
        /// Device endpoint ID
        id: String,
        /// Optional Ed25519 public key hash (hex)
        hash: Option<String>,
    },
    /// Untrust and remove devices by name
    Remove {
        /// Device name
        name: String,
    },
}

fn setup_cli_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hekadrop=info")),
        )
        .with_writer(stderr)
        .init();
}

// API: CLI prompts users for target device selection
#[expect(clippy::print_stderr, reason = "API: CLI prints to stderr")]
fn select_device(
    devices: &[DiscoveredDevice],
    to: Option<&str>,
) -> anyhow::Result<DiscoveredDevice> {
    if devices.is_empty() {
        anyhow::bail!("No HekaDrop/Quick Share devices discovered on the local network.");
    }

    if let Some(target) = to {
        let matched: Vec<&DiscoveredDevice> = devices
            .iter()
            .filter(|d| d.name.eq_ignore_ascii_case(target) || d.addr.to_string() == target)
            .collect();

        if matched.is_empty() {
            anyhow::bail!("No discovered device matches name or IP '{target}'.");
        }
        if matched.len() == 1 {
            return Ok(matched[0].clone());
        }

        eprintln!("⚠️ Multiple devices match '{target}':");
        for (idx, dev) in matched.iter().enumerate() {
            eprintln!("  [{}] {} ({})", idx + 1, dev.name, dev.addr);
        }
        if !stdin().is_terminal() {
            anyhow::bail!("Ambiguous target '{target}' in headless mode.");
        }
        loop {
            eprint!("👉 Choose device index: ");
            let _ = stderr().flush();
            let mut input = String::new();
            stdin().read_line(&mut input)?;
            if let Ok(idx) = input.trim().parse::<usize>() {
                if idx > 0 && idx <= matched.len() {
                    return Ok(matched[idx - 1].clone());
                }
            }
            eprintln!("Invalid choice.");
        }
    }

    if !stdin().is_terminal() {
        anyhow::bail!("Target device (--to) must be specified when running without TTY.");
    }

    eprintln!("\n🔍 Discovered HekaDrop/Quick Share devices:");
    for (idx, dev) in devices.iter().enumerate() {
        let ext = if dev.extension_supported {
            " [HekaDrop]"
        } else {
            " [Quick Share]"
        };
        eprintln!("  [{}] {} ({}{})", idx + 1, dev.name, dev.addr, ext);
    }

    loop {
        eprint!("👉 Choose device index: ");
        let _ = stderr().flush();
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx > 0 && idx <= devices.len() {
                return Ok(devices[idx - 1].clone());
            }
        }
        eprintln!("Invalid choice.");
    }
}

// API: CLI prints incoming connection notifications
#[expect(clippy::print_stderr, reason = "API: CLI prints to stderr")]
async fn run_receive(
    state: Arc<AppState>,
    accept_mode: AcceptMode,
    json_mode: bool,
) -> anyhow::Result<()> {
    let listener = hekadrop_core::server::start_listener().await?;
    let port = listener.local_addr()?.port();

    state.set_listen_port(port);

    if !json_mode {
        eprintln!("🚀 HekaDrop receiver listening on port {port}...");
    }

    let advertise_enabled = state.settings.read().advertise;
    let _mdns_handle = if advertise_enabled {
        let dev_name = state
            .settings
            .read()
            .resolved_device_name(crate::paths::device_name);
        if !json_mode {
            eprintln!("📡 Broadcasting via mDNS as '{dev_name}'...");
        }
        hekadrop_net::mdns::advertise(&dev_name, port)?
    } else {
        if !json_mode {
            eprintln!("⚠️ mDNS advertise disabled in settings (receive-only mode).");
        }
        None
    };

    let ui_port = Arc::new(CliUiPort::new(accept_mode));
    let platform_ops = Arc::new(CliPlatformOps);

    let _tracker = start_progress_tracker(state.clone(), json_mode);

    tokio::select! {
        res = hekadrop_core::server::accept_loop(listener, ui_port, state, platform_ops) => {
            if let Err(e) = res {
                eprintln!("❌ Receiver error: {e:?}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            if !json_mode {
                eprintln!("\n👋 Ctrl+C received, shutting down.");
            }
        }
    }

    Ok(())
}

#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "API: CLI prints to stdout/stderr"
)]
#[allow(clippy::too_many_lines)]
fn main() {
    let args = Cli::parse();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("❌ Error creating tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = rt.block_on(async {
        match args.command {
            Commands::ListPeers { scan_secs, json } => {
                setup_cli_logging();
                let _state = bootstrap::bootstrap(None)?;
                let duration = Duration::from_secs(scan_secs);
                if !json {
                    println!("🔍 Scanning for HekaDrop/Quick Share devices...");
                }
                let peers = hekadrop_net::discovery::scan(duration, 0).await?;
                if json {
                    let json_peers: Vec<serde_json::Value> = peers
                        .iter()
                        .map(|p| {
                            serde_json::json!({
                                "name": p.name,
                                "addr": p.addr.to_string(),
                                "port": p.port,
                                "device_type": p.device_type,
                                "extension_supported": p.extension_supported,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json_peers)?);
                } else {
                    println!("Found {} devices:", peers.len());
                    for peer in &peers {
                        let ext = if peer.extension_supported {
                            " [HekaDrop]"
                        } else {
                            " [Quick Share]"
                        };
                        println!("- {} ({}{})", peer.name, peer.addr, ext);
                    }
                }
            }
            Commands::Send {
                files,
                to,
                scan_secs,
                json,
            } => {
                setup_cli_logging();
                let state = bootstrap::bootstrap(None)?;
                if !json {
                    eprintln!("🔍 Scanning for HekaDrop/Quick Share devices...");
                }
                let peers =
                    hekadrop_net::discovery::scan(Duration::from_secs(scan_secs), 0).await?;
                let target = select_device(&peers, to.as_deref())?;
                if !json {
                    eprintln!("🚀 Sending files to {} ({})", target.name, target.addr);
                }

                let _tracker = start_progress_tracker(state.clone(), json);

                let req = hekadrop_core::sender::SendRequest {
                    device: target,
                    files,
                };

                Box::pin(hekadrop_core::sender::send(req, state)).await?;
                if !json {
                    eprintln!("✅ Send completed successfully!");
                }
            }
            Commands::SendText {
                text,
                to,
                scan_secs,
                json,
            } => {
                setup_cli_logging();
                let state = bootstrap::bootstrap(None)?;
                if !json {
                    eprintln!("🔍 Scanning for HekaDrop/Quick Share devices...");
                }
                let peers =
                    hekadrop_net::discovery::scan(Duration::from_secs(scan_secs), 0).await?;
                let target = select_device(&peers, to.as_deref())?;
                if !json {
                    eprintln!("🚀 Sending text to {} ({})", target.name, target.addr);
                }

                let _tracker = start_progress_tracker(state.clone(), json);

                let req = hekadrop_core::sender::SendTextRequest {
                    device: target,
                    text,
                };
                let ctx = hekadrop_core::sender::SendCtx {
                    text_summary: "text".to_string(),
                };

                Box::pin(hekadrop_core::sender::send_text(req, state, ctx)).await?;
                if !json {
                    eprintln!("✅ Text sent successfully!");
                }
            }
            Commands::Receive { accept, json } => {
                setup_cli_logging();
                let state = bootstrap::bootstrap(None)?;
                let accept_mode = match accept {
                    CliAcceptMode::Interactive => AcceptMode::Interactive,
                    CliAcceptMode::All => AcceptMode::All,
                    CliAcceptMode::Trusted => AcceptMode::Trusted,
                };
                run_receive(state, accept_mode, json).await?;
            }
            Commands::Trust { action } => {
                let state = bootstrap::bootstrap(None)?;
                match action {
                    TrustAction::List { json } => {
                        let settings = state.settings.read();
                        if json {
                            let devices: Vec<serde_json::Value> = settings
                                .trusted_devices
                                .iter()
                                .map(|d| {
                                    serde_json::json!({
                                        "name": d.name,
                                        "id": d.id,
                                        "secret_id_hash": d.secret_id_hash.map(hex::encode),
                                        "trusted_at_epoch": d.trusted_at_epoch,
                                    })
                                })
                                .collect();
                            println!("{}", serde_json::to_string_pretty(&devices)?);
                        } else {
                            println!("Trusted Devices:");
                            if settings.trusted_devices.is_empty() {
                                println!("  (No trusted devices found)");
                            }
                            for d in &settings.trusted_devices {
                                println!("- {}", d.display());
                                if let Some(hash) = d.secret_id_hash {
                                    println!("  Hash: {}", hex::encode(hash));
                                }
                                if d.trusted_at_epoch > 0 {
                                    println!("  Epoch: {}", d.trusted_at_epoch);
                                }
                            }
                        }
                    }
                    TrustAction::Add { name, id, hash } => {
                        let mut settings = state.settings.write().clone();
                        if let Some(hash_str) = hash {
                            let hash_bytes = hex::decode(&hash_str)?;
                            if hash_bytes.len() != 6 {
                                anyhow::bail!(
                                    "SHA-256 hash must be exactly 6 bytes (12 hex characters)"
                                );
                            }
                            let mut hash_arr = [0u8; 6];
                            hash_arr.copy_from_slice(&hash_bytes);
                            settings.add_trusted_with_hash(&name, &id, hash_arr);
                        } else {
                            settings.add_trusted(&name, &id);
                        }
                        settings.save(&paths::config_path())?;
                        println!("✅ Device '{name}' trusted successfully.");
                    }
                    TrustAction::Remove { name } => {
                        let mut settings = state.settings.write().clone();
                        settings.remove_trusted(&name);
                        settings.save(&paths::config_path())?;
                        println!("✅ Device '{name}' untrusted successfully.");
                    }
                }
            }
            Commands::Doctor => {
                println!("👨‍⚕️ HekaDrop CLI Diagnostic Report");
                println!("=====================================");

                println!("\n🔍 Scanning Network Interfaces:");
                match if_addrs::get_if_addrs() {
                    Ok(addrs) => {
                        for addr in addrs {
                            if !addr.is_loopback() {
                                println!("  Interface: {:<12} IP: {}", addr.name, addr.ip());
                            }
                        }
                    }
                    Err(e) => {
                        println!("  ❌ Error listing network interfaces: {e}");
                    }
                }

                let config_p = paths::config_path();
                println!("\n📁 Configuration Directories:");
                println!("  Config Path:      {}", config_p.display());
                if config_p.exists() {
                    println!("  ✅ config.json exists and is readable.");
                } else {
                    println!("  ⚠️ config.json does not exist. It will be created on startup.");
                }

                let identity_p = paths::identity_path();
                println!("  Identity Key:     {}", identity_p.display());
                if identity_p.exists() {
                    match hekadrop_core::identity::DeviceIdentity::load_or_create_at(&identity_p) {
                        Ok(identity) => {
                            println!("  ✅ identity.key is valid.");
                            println!(
                                "  🔒 Secret ID hash:  {}",
                                hex::encode(identity.secret_id_hash())
                            );
                        }
                        Err(e) => {
                            println!("  ❌ identity.key is invalid or unreadable: {e}");
                        }
                    }
                } else {
                    println!("  ⚠️ identity.key does not exist. A new key will be generated.");
                }
            }
            Commands::Version => {
                println!("HekaDrop CLI v0.10.0");
                println!("HekaDrop Core v0.8.0");
            }
            Commands::Daemon { config } => {
                setup_cli_logging();
                let state = bootstrap::bootstrap(config)?;
                let accept_mode = if state.settings.read().auto_accept {
                    AcceptMode::All
                } else {
                    AcceptMode::Trusted
                };
                if !state.settings.read().auto_accept {
                    eprintln!("🔐 Daemon starting in trusted-only mode. Only paired/trusted devices can send files.");
                } else {
                    eprintln!("⚠️ Daemon starting in auto-accept mode. Anyone on the local network can send files.");
                }
                run_receive(state, accept_mode, false).await?;
            }
        }
        anyhow::Ok(())
    }) {
        eprintln!("❌ Fatal error: {e}");
        std::process::exit(1);
    }
}
