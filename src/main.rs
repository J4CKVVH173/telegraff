use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    fs::OpenOptions,
    io::{IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
use telegraff::infrastructure::{
    agent::SocketTransport, config::Config, dns::Dns, hub, store::SqliteStore,
};

#[derive(Parser)]
#[command(version, about = "Scheduled TCP and UDP delivery monitoring")]
struct Cli {
    /// Show diagnostic details.
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
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
    /// Remove a registered agent and revoke its credential.
    Unregister {
        name: String,
        #[arg(long, default_value = "telegraff.toml")]
        config: PathBuf,
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
        /// Emit the detailed machine-readable report even in a terminal.
        #[arg(long)]
        json: bool,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Status {
        #[arg(long, default_value = "telegraff.toml")]
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
        #[arg(long, default_value = "telegraff.toml")]
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
    let cli = Cli::parse();
    telegraff::utils::set_verbose(cli.verbose);
    if let Err(e) = execute(cli).await {
        let error = if telegraff::utils::verbose() {
            format!("Error: {e:#}")
        } else {
            format!("Error: {e}")
        };
        eprintln!(
            "{}",
            telegraff::utils::paint(
                &error,
                31,
                telegraff::utils::color_enabled(std::io::stderr().is_terminal())
            )
        );
        std::process::exit(1);
    }
}
async fn execute(cli: Cli) -> Result<()> {
    let command = match cli.command {
        Some(command) => command,
        None if std::path::Path::new("telegraff.toml").exists() => {
            match load_config(std::path::Path::new("telegraff.toml"))? {
                Config::Hub(_) => Command::Hub {
                    config: "telegraff.toml".into(),
                    daemon: false,
                },
                Config::Agent(_) => Command::Agent {
                    config: "telegraff.toml".into(),
                    daemon: false,
                    once: false,
                    json: false,
                },
            }
        }
        None => Command::Setup,
    };
    match command {
        Command::Unregister { name, config } => {
            let Config::Hub(hub) = load_config(&config)? else {
                anyhow::bail!("Hub configuration required");
            };
            telegraff::infrastructure::registration::unregister(&hub, &name)?;
            telegraff::utils::message(&format!("Removed {name}"), 32);
            if cli.verbose {
                println!(
                    "Credential revoked; monitoring removed within 1s. History and exported profile retained."
                );
            }
        }
        Command::Setup => telegraff::infrastructure::setup::run()?,
        Command::Down { config } => telegraff::infrastructure::process::down(&config)?,
        Command::Register {
            name,
            config,
            port,
            offset,
            output,
        } => {
            let Config::Hub(hub) = load_config(&config)? else {
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
                telegraff::utils::message(&format!("Registered {name}: {}", output.display()), 32);
                println!("Copy {} to the agent; restart the hub.", output.display());
            }
            if cli.verbose {
                println!(
                    "Profile contains a private credential (0600); no separate key is needed."
                );
            }
        }
        Command::Hub { config, daemon } => {
            if daemon {
                return telegraff::infrastructure::process::start("hub", &config);
            }
            let _guard = telegraff::infrastructure::process::guard(&config)?;
            let Config::Hub(config) = load_config(&config)? else {
                anyhow::bail!("Hub configuration required")
            };
            hub::run(config, &Dns::new()?).await?;
        }
        Command::Agent {
            config,
            daemon,
            once,
            json,
        } => {
            if daemon {
                return telegraff::infrastructure::process::start("agent", &config);
            }
            let _guard = telegraff::infrastructure::process::guard(&config)?;
            let Config::Agent(config) = load_config(&config)? else {
                anyhow::bail!("Agent configuration required")
            };
            let settings = telegraff::application::agent::AgentSettings {
                policy: config.agent.policy(),
                hub: config.hub.clone(),
                port: config.port,
                timeout_seconds: config.timeout_seconds,
                auto: config.agent.auto,
            };
            let mut transport = SocketTransport::for_hub(
                telegraff::infrastructure::config::read_key(&config.agent.key_file)?,
                config.udp_bytes_per_second,
                &config.hub,
                config.tls,
                config.ca_file.as_deref(),
            )?;
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
                        let detail = if cli.verbose {
                            format!("{e:#}")
                        } else {
                            e.to_string()
                        };
                        eprintln!(
                            "{}",
                            telegraff::utils::paint(
                                &format!("Cycle failed: {detail}; retry scheduled"),
                                31,
                                telegraff::utils::color_enabled(std::io::stderr().is_terminal())
                            )
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_secs(settings.policy.interval)) => continue,
                            _ = tokio::signal::ctrl_c() => break,
                            _ = terminate.recv() => break,
                        }
                    }
                };
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    let color = telegraff::utils::color_enabled(std::io::stdout().is_terminal());
                    print!(
                        "{}",
                        if cli.verbose {
                            report.verbose_with_color(color)
                        } else {
                            report.human(color)
                        }
                    );
                }
                if once {
                    ensure!(report.successful(), "Delivery incomplete");
                    break;
                }
                if !report.successful() {
                    eprintln!(
                        "{}",
                        telegraff::utils::paint(
                            "Delivery incomplete; retry scheduled",
                            31,
                            telegraff::utils::color_enabled(std::io::stderr().is_terminal())
                        )
                    );
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
            let checked = load_config(&config)?;
            if let Config::Hub(hub) = &checked
                && let Some(tls) = &hub.tls
            {
                tls.acceptor(&hub.target)?;
            }
            if cli.verbose {
                println!("Configuration: {}", config.display());
            }
            println!(
                "{}",
                telegraff::utils::paint(
                    "Configuration valid",
                    32,
                    telegraff::utils::color_enabled(std::io::stdout().is_terminal())
                )
            );
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
            telegraff::utils::message("Key created", 32);
        }
        Command::Status { config, json } => {
            let Config::Hub(config) = load_config(&config)? else {
                anyhow::bail!("Run status on the hub; use agent --once here")
            };
            let state = SqliteStore::read(&config.database)
                .context("Cannot read hub state; start the hub first and check database access")?;
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
                print!(
                    "{}",
                    if cli.verbose {
                        status.verbose_with_color(
                            telegraff::utils::unix_time(),
                            telegraff::utils::color_enabled(std::io::stdout().is_terminal()),
                        )
                    } else {
                        status.human_with_color(
                            telegraff::utils::unix_time(),
                            telegraff::utils::color_enabled(std::io::stdout().is_terminal()),
                        )
                    }
                );
            }
        }
    }
    Ok(())
}

fn load_config(path: &std::path::Path) -> Result<Config> {
    let config = Config::load(path)?;
    if telegraff::utils::verbose() {
        telegraff::utils::log(&format!("Configuration: {}", path.display()), 36);
        match &config {
            Config::Hub(hub) => {
                telegraff::utils::log(
                    &format!(
                        "Hub: target={} public_port={:?} tcp={:?} udp={:?} database={} max_connections={} max_assemblies={} notifications={}",
                        hub.target,
                        hub.public_port,
                        hub.tcp_listen,
                        hub.udp_listen,
                        hub.database.display(),
                        hub.max_connections,
                        hub.max_assemblies,
                        hub.ntfy.is_some()
                    ),
                    36,
                );
                if let Some(tls) = &hub.tls {
                    let (certificate, key) = tls.paths(&hub.target)?;
                    telegraff::utils::log(
                        &format!(
                            "TLS: certificate={} key={}",
                            certificate.display(),
                            key.display()
                        ),
                        36,
                    );
                } else {
                    telegraff::utils::log("Native TLS: disabled", 36);
                }
                for entry in &hub.agents {
                    telegraff::utils::log(
                        &format!(
                            "Policy {}: interval={}s grace={}s offset={}s paused={} auto={} families={:?}",
                            entry.name,
                            entry.interval,
                            entry.grace,
                            entry.offset,
                            entry.paused,
                            entry.auto,
                            entry.families
                        ),
                        36,
                    );
                }
            }
            Config::Agent(agent) => {
                telegraff::utils::log(
                    &format!(
                        "Agent {}: hub={}:{} tls={:?} timeout={}s interval={}s udp_rate={} bytes/s",
                        agent.agent.name,
                        agent.hub,
                        agent.port,
                        agent.tls,
                        agent.timeout_seconds,
                        agent.agent.interval,
                        agent.udp_bytes_per_second
                    ),
                    36,
                );
            }
        }
    }
    Ok(config)
}
