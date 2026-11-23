use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

fn sidecar(config: &Path, extension: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let canonical = config
        .canonicalize()
        .context("Configuration does not exist")?;
    let uid = std::fs::metadata("/proc/self")?.uid();
    let root = std::env::temp_dir().join(format!("telegraff-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let metadata = std::fs::symlink_metadata(&root)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "Unsafe runtime directory"
    );
    use std::os::unix::ffi::OsStrExt;
    let digest = hex::encode(Sha256::digest(canonical.as_os_str().as_bytes()));
    Ok(root.join(format!("{digest}.{extension}")))
}
pub fn guard(config: &Path) -> Result<File> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(sidecar(config, "pid")?)?;
    file.try_lock()
        .context("Already running with this configuration")?;
    file.set_len(0)?;
    writeln!(file, "{}", std::process::id())?;
    file.sync_all()?;
    Ok(file)
}
pub fn start(role: &str, config: &Path) -> Result<()> {
    let checked = super::config::Config::load(config)?;
    if let super::config::Config::Hub(hub) = &checked
        && let Some(tls) = &hub.tls
    {
        tls.acceptor(&hub.target)?;
    }
    let config = config.canonicalize()?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(sidecar(&config, "pid")?)?;
    lock.try_lock()
        .context("Already running with this configuration")?;
    drop(lock);
    let log_path = sidecar(&config, "log")?;
    super::logging::prepare(&log_path)?;
    let mut logger = Command::new("setsid")
        .arg(std::env::current_exe()?)
        .arg("log-sink")
        .arg(&log_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Cannot start rotating log sink")?;
    let log = logger.stdin.take().context("Log pipe unavailable")?;
    use std::os::fd::AsFd;
    let stderr = log.as_fd().try_clone_to_owned()?;
    let mut child = Command::new("setsid")
        .arg(std::env::current_exe()?)
        .arg(role)
        .args(if crate::utils::verbose() {
            vec!["--verbose"]
        } else {
            vec![]
        })
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .inspect_err(|_| {
            let _ = logger.kill();
            let _ = logger.wait();
        })
        .context("Cannot start background process (setsid required)")?;
    std::thread::sleep(Duration::from_millis(300));
    if let Some(status) = child.try_wait()? {
        anyhow::bail!(
            "{role} failed ({status}); log: {}",
            sidecar(&config, "log")?.display()
        );
    }
    if logger.try_wait()?.is_some() {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!(
            "Rotating log sink failed; check runtime log permissions and free space: {}",
            log_path.display()
        );
    }
    crate::utils::message(&format!("Started {role}"), 32);
    if crate::utils::verbose() {
        println!(
            "Config: {}\nLog: {}\nPID: {}",
            config.display(),
            sidecar(&config, "log")?.display(),
            child.id()
        );
    }
    Ok(())
}
pub fn down(config: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(sidecar(config, "pid")?)
        .context("No process record for this configuration")?;
    if file.try_lock().is_ok() {
        crate::utils::message("Already stopped", 33);
        return Ok(());
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let pid: u32 = text.trim().parse().context("Invalid process record")?;
    ensure!(pid > 1, "Invalid process identifier");
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    // Atomic binary upgrades unlink the old inode while its process keeps
    // running. Linux appends this marker to /proc/PID/exe in that case.
    let executable_bytes = executable.as_os_str().as_encoded_bytes();
    let executable_path = executable_bytes
        .strip_suffix(b" (deleted)")
        .unwrap_or(executable_bytes);
    ensure!(
        executable_path == std::env::current_exe()?.as_os_str().as_encoded_bytes(),
        "Process executable differs; refusing to signal"
    );
    let args = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    let canonical = config.canonicalize()?;
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        args.split(|b| *b == 0)
            .any(|a| a == canonical.as_os_str().as_bytes()),
        "Process configuration differs; refusing to signal"
    );
    ensure!(
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()?
            .success(),
        "Cannot stop process"
    );
    for _ in 0..100 {
        if file.try_lock().is_ok() {
            crate::utils::message("Stopped", 32);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("Shutdown still in progress; retry down shortly")
}

/// Restart a daemon after its registry changes, preserving its working directory.
pub fn restart_hub_if_running(config: &Path) -> Result<()> {
    let record = sidecar(config, "pid")?;
    let mut file = match OpenOptions::new().read(true).write(true).open(&record) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if file.try_lock().is_ok() {
        return Ok(());
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let pid: u32 = text.trim().parse().context("Invalid process record")?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("Invalid process status")?
        .1
        .split_whitespace()
        .collect();
    // setsid daemons lead their own session. Foreground and supervised hubs
    // retain their existing lifecycle owner.
    if fields.get(3).and_then(|s| s.parse::<u32>().ok()) != Some(pid) {
        crate::utils::message(
            "Restart the foreground or supervised hub to load the registration.",
            33,
        );
        return Ok(());
    }
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    if cgroup.lines().any(|line| line.ends_with(".service")) {
        crate::utils::message("Restart the hub service to load the registration.", 33);
        return Ok(());
    }
    let checked = super::config::Config::load(config)?;
    let super::config::Config::Hub(hub) = checked else {
        anyhow::bail!("Hub configuration required");
    };
    if let Some(tls) = &hub.tls {
        tls.acceptor(&hub.target)?;
    }
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))?;
    let config = config.canonicalize()?;
    down(&config)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(cwd)
        .args(["hub", "-d", "--config"])
        .arg(config);
    if crate::utils::verbose() {
        command.arg("--verbose");
    }
    ensure!(
        command.status()?.success(),
        "Hub restart failed; registration is saved. Start the hub after correcting the startup error"
    );
    Ok(())
}
