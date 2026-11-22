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
    super::config::Config::load(config)?;
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
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(sidecar(&config, "log")?)?;
    let mut child = Command::new("setsid")
        .arg(std::env::current_exe()?)
        .arg(role)
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("Cannot start background process (setsid required)")?;
    std::thread::sleep(Duration::from_millis(300));
    if let Some(status) = child.try_wait()? {
        anyhow::bail!("Background process exited ({status}); inspect the configuration .log file");
    }
    println!(
        "Started {role}; use telegraff down --config {} to stop. Logs: {}",
        config.display(),
        sidecar(&config, "log")?.display()
    );
    Ok(())
}
pub fn down(config: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(sidecar(config, "pid")?)
        .context("No process record for this configuration")?;
    if file.try_lock().is_ok() {
        println!("Already stopped");
        return Ok(());
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let pid: u32 = text.trim().parse().context("Invalid process record")?;
    ensure!(pid > 1, "Invalid process identifier");
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    ensure!(
        executable == std::env::current_exe()?,
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
            println!("Stopped");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("Shutdown still in progress; retry down shortly")
}
