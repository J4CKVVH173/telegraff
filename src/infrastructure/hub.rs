use super::{
    config::HubConfig,
    notification::Ntfy,
    receiver::{self, Intake},
    store::SqliteStore,
};
use crate::{
    application::{
        Monitor, Policy,
        ports::{Notifier, Repository, Resolver},
    },
    utils::unix_time,
};
use anyhow::{Result, ensure};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::timeout,
};

pub async fn run(config: HubConfig, resolver: &impl Resolver) -> Result<()> {
    let registry = receiver::registry(&config.agents)?;
    let mut store = SqliteStore::open(&config.database)?;
    let state = store.load()?;
    let policies: Vec<Policy> = config
        .agents
        .iter()
        .map(|a| {
            let mut p = a.policy();
            if a.auto {
                p.families = state.enrolled.get(&a.name).cloned().unwrap_or_default();
            }
            p
        })
        .collect();
    let mut monitor = Monitor {
        state,
        policies,
        reminder: config.reminder_seconds,
        retention: config.retention_days * 86400,
    };
    monitor.restart(unix_time());
    store.save(&monitor.state)?;
    let (tx, mut rx) = mpsc::channel::<Intake>(256);
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    for addr in &config.tcp_listen {
        tasks.spawn(receiver::tcp_loop(
            receiver::bind_tcp(*addr)?,
            registry.clone(),
            tx.clone(),
            permits.clone(),
        ));
    }
    for addr in &config.udp_listen {
        tasks.spawn(receiver::udp_loop(
            receiver::bind_udp(*addr)?,
            registry.clone(),
            tx.clone(),
            config.max_assemblies,
        ));
    }
    let (notify_tx, mut notify_rx) = mpsc::channel::<(u64, String)>(1);
    let (outcome_tx, mut outcome_rx) = mpsc::channel::<(u64, bool)>(1);
    let has_notifier = config.ntfy.is_some();
    if let Some(n) = &config.ntfy {
        let notifier = Ntfy::new(n)?;
        tasks.spawn(async move {
            while let Some((id, text)) = notify_rx.recv().await {
                let ok = notifier.publish(&text).await.is_ok();
                if outcome_tx.send((id, ok)).await.is_err() {
                    break;
                }
            }
            Ok(())
        });
    }
    let mut in_flight = false;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut dns_tick = tokio::time::interval(Duration::from_secs(60));
    let (dns_tx, mut dns_rx) = mpsc::channel(1);
    let mut resolving = false;
    // DNS work is bounded separately so a resolver timeout cannot stop intake.
    let mut dns_future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> =
        Box::pin(std::future::pending());
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!("Hub started; agents={}", config.agents.len());
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            task = tasks.join_next(), if !tasks.is_empty() => {
                match task {Some(Ok(Ok(()))) => anyhow::bail!("Hub worker stopped"), _ => anyhow::bail!("Hub worker failed")}
            }
            Some(intake) = rx.recv() => {
                let (accepted,name) = match intake.event {
                    receiver::Incoming::Transfer(result) => { let name=result.agent.clone(); (monitor.accept(result,unix_time()),name) },
                    receiver::Incoming::Dns(name,observation) => {
                        monitor.observe_agent_dns(&name,observation);
                        (true,name)
                    }
                };
                if accepted { store.save(&monitor.state)?; }
                let families = monitor.policies.iter().find(|p|p.name==name).map(|p|p.families.clone()).unwrap_or_default();
                let _ = intake.accepted.send(receiver::IntakeReply {accepted,families});
            }
            _ = tick.tick() => {
                let now = unix_time();
                monitor.tick(now);
                store.save(&monitor.state)?;
                if has_notifier && !in_flight && let Some(n) = monitor.state.notification_due(now) {
                        notify_tx.send((n.id,n.text.clone())).await?;
                        in_flight = true;
                }
            }
            Some((id,ok)) = outcome_rx.recv() => {
                in_flight = false;
                ensure!(monitor.state.complete_notification(id,ok,unix_time()), "Notification order mismatch");
                if !ok { eprintln!("Notification delivery failed; retry scheduled"); }
                store.save(&monitor.state)?;
            }
            _ = dns_tick.tick(), if !resolving => {
                resolving = true;
                let sender = dns_tx.clone();
                let host = config.target.clone();
                dns_future = Box::pin(async move {
                    let result = timeout(Duration::from_secs(10),resolver.resolve(&host)).await.ok().and_then(Result::ok);
                    let _ = sender.send(result).await;
                });
            }
            _ = &mut dns_future, if resolving => { resolving = false; dns_future = Box::pin(std::future::pending()); }
            Some(resolution) = dns_rx.recv() => {
                let now = unix_time();
                let automatic = config.agents.iter().filter(|a|a.auto).map(|a|a.name.clone()).collect::<Vec<_>>();
                monitor.observe_dns(resolution.as_ref(),&automatic,now);
                store.save(&monitor.state)?;
            }
        }
    }
    store.save(&monitor.state)?;
    tasks.abort_all();
    eprintln!("Hub stopped");
    Ok(())
}
