//! A separate streaming sink bounds every byte written by detached stdout/stderr.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
pub const MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const ARCHIVES: usize = 3;
struct RotatingLog {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    limit: u64,
    archives: usize,
}
impl RotatingLog {
    fn open(path: &Path, limit: u64, archives: usize) -> Result<Self> {
        ensure!(limit > 0 && archives > 0, "Invalid log limits");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        let mut bytes = file.metadata()?.len();
        // Upgrade an existing oversized log without allocating its entire contents.
        if bytes > limit {
            file.seek(SeekFrom::End(-(limit as i64)))?;
            let mut tail = Vec::with_capacity(limit as usize);
            (&mut file).take(limit).read_to_end(&mut tail)?;
            file.set_len(0)?;
            file.write_all(&tail)?;
            bytes = limit;
        }
        Ok(Self {
            path: path.to_owned(),
            file: Some(file),
            bytes,
            limit,
            archives,
        })
    }
    fn archive(&self, index: usize) -> PathBuf {
        self.path.with_file_name(format!(
            "{}.{}",
            self.path.file_name().unwrap().to_string_lossy(),
            index
        ))
    }
    fn rotate(&mut self) -> Result<()> {
        self.file.take();
        for index in (1..self.archives).rev() {
            let from = self.archive(index);
            if from.exists() {
                std::fs::rename(from, self.archive(index + 1))?;
            }
        }
        std::fs::rename(&self.path, self.archive(1))?;
        self.file = Some(
            OpenOptions::new()
                .create_new(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)?,
        );
        self.bytes = 0;
        Ok(())
    }
    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            if self.bytes == self.limit {
                self.rotate()?;
            }
            let n = bytes.len().min((self.limit - self.bytes) as usize);
            self.file.as_mut().unwrap().write_all(&bytes[..n])?;
            self.bytes += n as u64;
            bytes = &bytes[n..];
        }
        Ok(())
    }
}
pub fn prepare(path: &Path) -> Result<()> {
    RotatingLog::open(path, MAX_BYTES, ARCHIVES).map(|_| ())
}
pub fn sink(path: &Path) -> Result<()> {
    let mut log =
        RotatingLog::open(path, MAX_BYTES, ARCHIVES).context("Cannot open rotating daemon log")?;
    let mut input = std::io::stdin().lock();
    let mut buffer = [0; 8192];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        log.write(&buffer[..n])?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_writes_rotate_with_exact_bounds_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut log = RotatingLog::open(&path, 8, 2).unwrap();
        log.write(b"12345678abcdefghABCDEFGHtail").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"tail");
        assert_eq!(std::fs::read(log.archive(1)).unwrap(), b"ABCDEFGH");
        assert_eq!(std::fs::read(log.archive(2)).unwrap(), b"abcdefgh");
        drop(log);
        RotatingLog::open(&path, 8, 2)
            .unwrap()
            .write(b"67890")
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"0");
        assert_eq!(
            std::fs::read(dir.path().join("daemon.log.1")).unwrap(),
            b"tail6789"
        );
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let m = entry.unwrap().metadata().unwrap();
            assert!(m.len() <= 8);
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
    }
    #[test]
    fn existing_oversized_log_keeps_only_its_bounded_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.log");
        std::fs::write(&path, b"oldest--new-tail").unwrap();
        drop(RotatingLog::open(&path, 8, 2).unwrap());
        assert_eq!(std::fs::read(path).unwrap(), b"new-tail");
    }
}
