use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};
use telegraff::infrastructure::{
    agent::SocketTransport, config::Config, dns::Dns, hub, store::SqliteStore,
};

#[derive(Parser)]
#[command(version, about = "Scheduled TCP and UDP delivery monitoring")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Interactive first-time configuration.
    Setup,
    /// Stop a background hub or agent using this configuration.
    Down {
        #[arg(long, default_value = "telegraff.toml")]
        config: PathBuf,
    },
    /// Register a server and create its private agent profile.
    Register {
        name: String,
        #[arg(long, default_value = "telegraff.toml")]
        config: PathBuf,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Write a ready-to-copy private agent configuration.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Hub {
        #[arg(long, default_value = "telegraff.toml")]
        config: PathBuf,
        #[arg(short = 'd', long)]
        daemon: bool,
    },
    Agent {
        #[arg(long, default_value = "telegraff.toml")]
        config: PathBuf,
        #[arg(short = 'd', long)]
        daemon: bool,
        /// Perform a single diagnostic cycle.
        #[arg(long)]
        once: bool,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}
#[derive(Subcommand)]
enum ConfigCommand {
    Check {
        #[arg(long)]
        config: PathBuf,
    },
}
#[derive(Subcommand)]
enum KeyCommand {
    Generate {
        #[arg(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = execute(Cli::parse()).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
async fn execute(cli: Cli) -> Result<()> {
    let command = match cli.command {
        Some(command) => command,
        None if std::path::Path::new("telegraff.toml").exists() => {
            match Config::load(std::path::Path::new("telegraff.toml"))? {
                Config::Hub(_) => Command::Hub {
                    config: "telegraff.toml".into(),
                    daemon: false,
                },
                Config::Agent(_) => Command::Agent {
                    config: "telegraff.toml".into(),
                    daemon: false,
                    once: false,
                },
            }
        }
        None => Command::Setup,
    };
    match command {
        Command::Setup => telegraff::infrastructure::setup::run()?,
        Command::Down { config } => telegraff::infrastructure::process::down(&config)?,
        Command::Register {
            name,
            config,
            port,
            offset,
            output,
        } => {
            let Config::Hub(hub) = Config::load(&config)? else {
                anyhow::bail!("Hub configuration required")
            };
            let output = Some(output.unwrap_or_else(|| PathBuf::from(format!("{name}.toml"))));
            if let Some(ref output) = output {
                ensure!(
                    !output.exists(),
                    "Output already exists; refusing to overwrite"
                );
            }
            let path =
                telegraff::infrastructure::registration::register(&hub, &name, port, offset)?;
            if let Some(output) = output {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&output)
                    .context("Cannot create agent configuration; destination must not exist")?;
                file.write_all(&std::fs::read(&path)?)?;
                file.sync_all()?;
                println!(
                    "Ready-to-copy agent configuration: {} (contains secret; mode 0600)",
                    output.display()
                );
            }
            println!(
                "Registered {name}. Copy {} to the agent as /etc/telegraff/agent.toml (mode 0600). Restart the hub to load this registration.",
                path.display()
            );
        }
        Command::Hub { config, daemon } => {
            if daemon {
                return telegraff::infrastructure::process::start("hub", &config);
            }
            let _guard = telegraff::infrastructure::process::guard(&config)?;
            let Config::Hub(config) = Config::load(&config)? else {
                anyhow::bail!("Hub configuration required")
            };
            hub::run(config, &Dns::new()?).await?;
        }
        Command::Agent {
            config,
            daemon,
            once,
        } => {
            if daemon {
                return telegraff::infrastructure::process::start("agent", &config);
            }
            let _guard = telegraff::infrastructure::process::guard(&config)?;
            let Config::Agent(config) = Config::load(&config)? else {
                anyhow::bail!("Agent configuration required")
            };
            let settings = telegraff::application::agent::AgentSettings {
                policy: config.agent.policy(),
                hub: config.hub,
                port: config.port,
                timeout_seconds: config.timeout_seconds,
                auto: config.agent.auto,
            };
            let mut transport = SocketTransport::new(
                telegraff::infrastructure::config::read_key(&config.agent.key_file)?,
                config.udp_bytes_per_second,
            );
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let resolver = Dns::new()?;
            loop {
                let result = tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = terminate.recv() => break,
                result = tokio::time::timeout(
                    std::time::Duration::from_secs(settings.timeout_seconds),
                    telegraff::application::agent::run(
                        &settings,
                        &resolver,
                        &mut transport,
                        &telegraff::infrastructure::SystemClock,
                    ),
                ) => result.context("Cycle deadline exceeded").and_then(|r| r),
                };
                let report = match result {
                    Ok(report) => report,
                    Err(e) if once => return Err(e),
                    Err(e) => {
                        eprintln!("Cycle failed: {e}; will retry after interval");
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_secs(settings.policy.interval)) => continue,
                            _ = tokio::signal::ctrl_c() => break,
                            _ = terminate.recv() => break,
                        }
                    }
                };
                println!("{}", serde_json::to_string_pretty(&report)?);
                if once {
                    ensure!(
                        report.successful(),
                        "One or more expected channels lack a successful receipt; hub intake may differ"
                    );
                    break;
                }
                if !report.successful() {
                    eprintln!("Access check failed for one or more channels; retry scheduled");
                }
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(settings.policy.interval)) => {},
                    _ = tokio::signal::ctrl_c() => break,
                    _ = terminate.recv() => break,
                }
            }
        }
        Command::Config {
            command: ConfigCommand::Check { config },
        } => {
            Config::load(&config)?;
            println!("Configuration valid");
        }
        Command::Key {
            command: KeyCommand::Generate { output },
        } => {
            let key: [u8; 32] = rand::random();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output)
                .context("Cannot create key file; destination must not exist")?;
            writeln!(file, "{}", hex::encode(key))?;
            file.sync_all()?;
            println!("Key file created");
        }
        Command::Status { config, json } => {
            let Config::Hub(config) = Config::load(&config)? else {
                anyhow::bail!("Hub configuration required")
            };
            let state = SqliteStore::read(&config.database)?;
            let policies = config
                .agents
                .iter()
                .map(|entry| {
                    let mut p = entry.policy();
                    if entry.auto {
                        p.families = state.enrolled.get(&entry.name).cloned().unwrap_or_default();
                    }
                    p
                })
                .collect::<Vec<_>>();
            let status = telegraff::application::status::Status::new(&state, &policies);
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "Last observation: {} | queued notifications: {}",
                    status.last_observation, status.queued_notifications
                );
                for agent in &status.agents {
                    println!(
                        "{} {} enrollment_failures={}",
                        agent.name, agent.overall, agent.enrollment_failures
                    );
                    for c in &agent.channels {
                        println!(
                            "  {} {} failures={} last_success={:?} bytes={} udp_loss_pct={}",
                            c.channel,
                            c.state,
                            c.failures,
                            c.last_success,
                            c.accepted_bytes,
                            c.udp_loss_percent
                                .map(|loss| format!("{loss:.2}"))
                                .unwrap_or_else(|| "n/a".into())
                        );
                    }
                }
                for (role, summary) in &status.dns {
                    println!("DNS {role}: {summary}");
                }
                for (start, end) in &status.observation_gaps {
                    println!("Observation gap: {start}..{end}");
                }
            }
        }
    }
    Ok(())
}
