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
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Hub {
        #[arg(long)]
        config: PathBuf,
    },
    Agent {
        #[arg(long)]
        config: PathBuf,
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
    match cli.command {
        Command::Hub { config } => {
            let Config::Hub(config) = Config::load(&config)? else {
                anyhow::bail!("Hub configuration required")
            };
            hub::run(config, &Dns::new()?).await?;
        }
        Command::Agent { config } => {
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
            let report = tokio::time::timeout(
                std::time::Duration::from_secs(settings.timeout_seconds),
                telegraff::application::agent::run(
                    &settings,
                    &Dns::new()?,
                    &mut transport,
                    &telegraff::infrastructure::SystemClock,
                ),
            )
            .await
            .context("Cycle deadline exceeded")??;
            println!("{}", serde_json::to_string_pretty(&report)?);
            ensure!(
                report.successful(),
                "One or more expected channels lack a successful receipt; hub intake may differ"
            );
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
