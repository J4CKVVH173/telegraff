use crate::application::{State, Transfer, ports::Repository};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};
const MAX_METADATA: usize = 8 * 1024 * 1024;
const MAX_TRANSFER: usize = 4096;
pub struct SqliteStore {
    connection: Connection,
    saved: HashMap<String, Transfer>,
    records: usize,
}
impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_bounded(path, 100_000, 256, 30)
    }
    pub fn open_bounded(
        path: &Path,
        records: usize,
        max_mib: u64,
        retention_days: u64,
    ) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        ensure!(
            records > 0 && (16..=16384).contains(&max_mib),
            "Invalid database bounds"
        );
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .context("Cannot create state database")?;
        let connection = Connection::open(path).context("Cannot open state database")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        // TRUNCATE avoids an ever-growing WAL pinned by long-lived status readers.
        // The rollback journal is emptied after every committed transaction.
        connection.execute_batch("PRAGMA journal_mode=TRUNCATE; PRAGMA synchronous=FULL; PRAGMA journal_size_limit=0; PRAGMA cache_size=-4096; PRAGMA mmap_size=0; PRAGMA temp_store=FILE;")?;
        let vacuum: u32 = connection.pragma_query_value(None, "auto_vacuum", |r| r.get(0))?;
        connection.execute_batch("PRAGMA auto_vacuum=FULL;
            CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, cycle INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS transfers_cycle ON transfers(cycle);
            CREATE INDEX IF NOT EXISTS transfers_cycle_id ON transfers(cycle,id);")?;
        // Use persisted hub time so a first open cannot erase a restored database
        // merely because the machine clock differs from the recorded observation.
        let observed: Option<String> = connection
            .query_row("SELECT version,body FROM state WHERE id=1", [], |r| {
                let bytes: usize = r.get_ref(1)?.as_str()?.len();
                if bytes > MAX_METADATA || r.get::<_, u32>(0)? != 1 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                r.get(1)
            })
            .optional()?;
        if let Some(body) = observed {
            let state: State =
                serde_json::from_str(&body).context("Cannot read persisted hub state")?;
            let oldest = state
                .observed_until
                .saturating_sub(retention_days.saturating_mul(86400));
            connection.execute("DELETE FROM transfers WHERE cycle < ?1", [oldest])?;
        }
        Self::trim(&connection, records)?;
        if vacuum != 1 {
            connection.execute_batch("VACUUM;").context("Cannot enable database space reclamation; ensure temporary disk space is available")?;
        }
        let page_size: u64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let pages = max_mib * 1024 * 1024 / page_size;
        connection.pragma_update(None, "max_page_count", pages)?;
        let actual: u64 = connection.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
        ensure!(
            actual <= pages,
            "Database exceeds database_max_mib after history cleanup; increase the configured cap"
        );
        Ok(Self {
            connection,
            saved: HashMap::new(),
            records,
        })
    }
    fn trim(connection: &Connection, records: usize) -> Result<()> {
        connection.execute("DELETE FROM transfers WHERE (cycle,id) < (SELECT cycle,id FROM transfers ORDER BY cycle DESC,id DESC LIMIT 1 OFFSET ?1)",[records.saturating_sub(1) as u64])?;
        Ok(())
    }
    pub fn read(path: &Path) -> Result<State> {
        Self::read_bounded(path, 100_000)
    }
    pub fn read_bounded(path: &Path, records: usize) -> Result<State> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .context("Cannot open hub database; start the hub first")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA cache_size=-4096; PRAGMA mmap_size=0;")?;
        Self {
            connection,
            saved: HashMap::new(),
            records,
        }
        .load()
    }
}
impl Repository for SqliteStore {
    fn load(&self) -> Result<State> {
        let row: Option<(u32, String)> = self
            .connection
            .query_row("SELECT version,body FROM state WHERE id=1", [], |r| {
                if r.get_ref(1)?.as_str()?.len() > MAX_METADATA {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let mut state: State = match row {
            Some((1, body)) => serde_json::from_str(&body)?,
            Some(_) => anyhow::bail!("Unsupported state schema"),
            None => State::default(),
        };
        // Legacy metadata may contain transfers; new snapshots keep them in SQL only.
        state.bound_history(self.records);
        let mut query=self.connection.prepare("SELECT body FROM (SELECT cycle,id,body FROM transfers ORDER BY cycle DESC,id DESC LIMIT ?1) ORDER BY cycle,id")?;
        for body in query.query_map([self.records as u64], |r| {
            if r.get_ref(0)?.as_str()?.len() > MAX_TRANSFER {
                return Err(rusqlite::Error::InvalidQuery);
            }
            r.get::<_, String>(0)
        })? {
            state.transfers.push(serde_json::from_str(&body?)?);
        }
        state.bound_history(self.records);
        Ok(state)
    }
    fn save(&mut self, state: &State) -> Result<()> {
        ensure!(
            state.transfers.len() <= self.records,
            "In-memory history exceeds max_transfer_records"
        );
        let mut metadata = State {
            channels: state.channels.clone(),
            enrolled: state.enrolled.clone(),
            enrollment_failures: state.enrollment_failures.clone(),
            dns: state.dns.clone(),
            transfers: Vec::new(),
            outbox: state.outbox.clone(),
            next_notification: state.next_notification,
            cycle_anchors: state.cycle_anchors.clone(),
            cycle_tokens: state.cycle_tokens.clone(),
            retired_tokens: state.retired_tokens.clone(),
            discarded_notifications: state.discarded_notifications,
            observed_until: state.observed_until,
            gaps: state.gaps.clone(),
        };
        metadata.bound_history(0);
        let body = serde_json::to_string(&metadata)?;
        ensure!(
            body.len() <= MAX_METADATA,
            "Hub metadata exceeds 8 MiB; reduce configured agent count or pending state"
        );
        let tx = self.connection.transaction()?;
        // Free old rows before inserting new ones so a full bounded database can progress.
        let oldest = state
            .transfers
            .iter()
            .map(|t| t.cycle)
            .min()
            .unwrap_or(state.observed_until);
        tx.execute("DELETE FROM transfers WHERE cycle < ?1", [oldest])?;
        tx.execute("INSERT INTO state(id,version,body) VALUES(1,1,?1) ON CONFLICT(id) DO UPDATE SET body=excluded.body",[body])?;
        let mut changed = Vec::new();
        let mut live = HashSet::new();
        for t in &state.transfers {
            let id = format!(
                "{}:{}:{}:{}",
                t.agent,
                t.cycle,
                t.channel.label(),
                t.transfer
            );
            live.insert(id.clone());
            if self.saved.get(&id) != Some(t) {
                let value = serde_json::to_string(t)?;
                ensure!(
                    value.len() <= MAX_TRANSFER,
                    "Transfer record exceeds 4096 bytes"
                );
                tx.execute("INSERT INTO transfers(id,cycle,body) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET body=excluded.body",params![id,t.cycle,value])?;
                changed.push((id, t.clone()));
            }
        }
        Self::trim(&tx, self.records)?;
        tx.commit()
            .context("Cannot persist monitoring state (check database cap and free disk space)")?;
        self.saved.extend(changed);
        self.saved.retain(|id, _| live.contains(id));
        Ok(())
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn legacy_wal_migrates_reclaims_space_and_enforces_database_page_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        {
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE legacy_blob(body BLOB); INSERT INTO legacy_blob VALUES(zeroblob(8388608)); DELETE FROM legacy_blob;").unwrap();
        }
        let before = std::fs::metadata(&path).unwrap().len();
        let store = SqliteStore::open_bounded(&path, 100, 16, 30).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < before);
        let mode: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "truncate");
        let vacuum: u32 = store
            .connection
            .pragma_query_value(None, "auto_vacuum", |r| r.get(0))
            .unwrap();
        assert_eq!(vacuum, 1);
        let error = store
            .connection
            .execute("INSERT INTO legacy_blob VALUES(zeroblob(20971520))", [])
            .unwrap_err();
        assert!(
            matches!(error,rusqlite::Error::SqliteFailure(e,_) if e.code==rusqlite::ErrorCode::DiskFull)
        );
        assert!(std::fs::metadata(&path).unwrap().len() <= 16 * 1024 * 1024);
        store
            .connection
            .execute("INSERT INTO legacy_blob VALUES(zeroblob(8388608))", [])
            .unwrap();
        let grown = std::fs::metadata(&path).unwrap().len();
        store
            .connection
            .execute("DELETE FROM legacy_blob", [])
            .unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < grown);
        assert_eq!(
            std::fs::metadata(path.with_file_name("state.sqlite-journal"))
                .unwrap()
                .len(),
            0
        );
    }
}
