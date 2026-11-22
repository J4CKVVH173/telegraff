use crate::application::{State, Transfer, ports::Repository};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::{collections::HashMap, path::Path};

pub struct SqliteStore {
    connection: Connection,
    saved: HashMap<String, Transfer>,
}
impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .context("Cannot create state database")?;
        let connection = Connection::open(path).context("Cannot open state database")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, cycle INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS transfers_cycle ON transfers(cycle);")?;
        Ok(Self {
            connection,
            saved: HashMap::new(),
        })
    }
    pub fn read(path: &Path) -> Result<State> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .context("Cannot open hub database; start the hub first")?;
        Self {
            connection,
            saved: HashMap::new(),
        }
        .load()
    }
}
impl Repository for SqliteStore {
    fn load(&self) -> Result<State> {
        let row: Option<(u32, String)> = self
            .connection
            .query_row("SELECT version, body FROM state WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let mut state = match row {
            Some((1, body)) => serde_json::from_str(&body)?,
            Some(_) => anyhow::bail!("Unsupported state schema"),
            None => State::default(),
        };
        let mut query = self
            .connection
            .prepare("SELECT body FROM transfers ORDER BY cycle,id")?;
        for body in query.query_map([], |r| r.get::<_, String>(0))? {
            state.transfers.push(serde_json::from_str(&body?)?);
        }
        Ok(state)
    }
    fn save(&mut self, state: &State) -> Result<()> {
        let metadata = State {
            channels: state.channels.clone(),
            enrolled: state.enrolled.clone(),
            enrollment_failures: state.enrollment_failures.clone(),
            dns: state.dns.clone(),
            transfers: Vec::new(),
            outbox: state.outbox.clone(),
            next_notification: state.next_notification,
            cycle_anchors: state.cycle_anchors.clone(),
            cycle_tokens: state.cycle_tokens.clone(),
            observed_until: state.observed_until,
            gaps: state.gaps.clone(),
        };
        let body = serde_json::to_string(&metadata)?;
        let tx = self.connection.transaction()?;
        tx.execute("INSERT INTO state(id,version,body) VALUES(1,1,?1) ON CONFLICT(id) DO UPDATE SET body=excluded.body", [body])?;
        let mut changed = Vec::new();
        for t in &state.transfers {
            let id = format!(
                "{}:{}:{}:{}",
                t.agent,
                t.cycle,
                t.channel.label(),
                t.transfer
            );
            if self.saved.get(&id) != Some(t) {
                let value = serde_json::to_string(t)?;
                tx.execute("INSERT INTO transfers(id,cycle,body) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET body=excluded.body",params![id,t.cycle,value])?;
                changed.push((id, t.clone()));
            }
        }
        let oldest = state
            .transfers
            .iter()
            .map(|t| t.cycle)
            .min()
            .unwrap_or(state.observed_until);
        tx.execute("DELETE FROM transfers WHERE cycle < ?1", [oldest])?;
        tx.commit()?;
        self.saved.extend(changed);
        self.saved.retain(|_, transfer| transfer.cycle >= oldest);
        Ok(())
    }
}
