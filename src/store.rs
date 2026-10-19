//! Server state in SQLite: enrolled devices, their FIDO2 credentials, and an audit log.
//! Holds only public data (public keys, counters). The server's secret key lives in keys.rs.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::fido::StoredCredential;
use crate::proto::Alg;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("unknown algorithm {0:?} in database")]
    UnknownAlg(String),
    #[error("stored endpoint id has {0} bytes, expected 32")]
    BadId(usize),
}

/// One enrolled device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub endpoint_id: [u8; 32],
    pub name: String,
    pub routes: Vec<String>,
}

#[derive(Debug)]
pub struct Store {
    // One connection behind a lock: login traffic is tiny, so this is plenty.
    db: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS devices (
    endpoint_id BLOB PRIMARY KEY CHECK (length(endpoint_id) = 32),
    name        TEXT NOT NULL UNIQUE,
    routes      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    credential_id BLOB PRIMARY KEY,
    endpoint_id   BLOB NOT NULL REFERENCES devices(endpoint_id) ON DELETE CASCADE,
    alg           TEXT NOT NULL CHECK (alg IN ('es256', 'eddsa')),
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
CREATE TABLE IF NOT EXISTS audit_log (
    ts          INTEGER NOT NULL,
    endpoint_id BLOB,
    event       TEXT NOT NULL,
    detail      TEXT
);
";

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::init(Connection::open(path)?)
    }

    /// A throwaway database for tests.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> Result<Self, StoreError> {
        // journal_mode answers with the mode it chose ("wal", or "memory" in tests); we don't need it.
        db.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
        db.pragma_update(None, "foreign_keys", "ON")?; // off by default in SQLite!
        db.execute_batch(SCHEMA)?;
        Ok(Store { db: Mutex::new(db) })
    }

    /// Adds a device (or updates its name and routes) and attaches one credential.
    /// Call it once per security key, so a backup YubiKey is just a second call.
    pub fn enroll(
        &self,
        endpoint_id: &[u8; 32],
        name: &str,
        routes: &[String],
        credential_id: &[u8],
        alg: Alg,
        public_key: &[u8],
    ) -> Result<(), StoreError> {
        let mut db = self.db.lock().unwrap(); // only fails if another thread panicked mid-query
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO devices (endpoint_id, name, routes, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(endpoint_id) DO UPDATE SET name = excluded.name, routes = excluded.routes",
            params![&endpoint_id[..], name, routes.join(","), now()],
        )?;
        tx.execute(
            "INSERT INTO credentials (credential_id, endpoint_id, alg, public_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                credential_id,
                &endpoint_id[..],
                alg_name(alg),
                public_key,
                now()
            ],
        )?;
        tx.execute(
            "INSERT INTO audit_log (ts, endpoint_id, event, detail) VALUES (?1, ?2, 'enroll', ?3)",
            params![now(), &endpoint_id[..], name],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The device with this endpoint id, or None if it isn't enrolled.
    pub fn device(&self, endpoint_id: &[u8; 32]) -> Result<Option<Device>, StoreError> {
        let db = self.db.lock().unwrap();
        let row = db
            .query_row(
                "SELECT name, routes FROM devices WHERE endpoint_id = ?1",
                params![&endpoint_id[..]],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(row.map(|(name, routes)| Device {
            endpoint_id: *endpoint_id,
            name,
            routes: split_routes(&routes),
        }))
    }

    /// Every credential enrolled for this device, as (credential id, what verify needs).
    pub fn credentials(
        &self,
        endpoint_id: &[u8; 32],
    ) -> Result<Vec<(Vec<u8>, StoredCredential)>, StoreError> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT credential_id, alg, public_key, sign_count FROM credentials WHERE endpoint_id = ?1",
        )?;
        let rows = stmt.query_map(params![&endpoint_id[..]], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, u32>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, alg, public_key, sign_count) = row?;
            out.push((
                id,
                StoredCredential {
                    alg: parse_alg(&alg)?,
                    public_key,
                    sign_count,
                },
            ));
        }
        Ok(out)
    }

    /// Stores a new counter, but only if the stored one is still `old`.
    /// If two logins race with the same counter, exactly one wins.
    pub fn bump_counter(
        &self,
        credential_id: &[u8],
        old: u32,
        new: u32,
    ) -> Result<bool, StoreError> {
        let db = self.db.lock().unwrap();
        let changed = db.execute(
            "UPDATE credentials SET sign_count = ?3, last_used_at = ?4
             WHERE credential_id = ?1 AND sign_count = ?2",
            params![credential_id, old, new, now()],
        )?;
        Ok(changed == 1)
    }

    /// Removes a device and (by cascade) all its credentials. Returns false if it didn't exist.
    pub fn remove_device(&self, endpoint_id: &[u8; 32]) -> Result<bool, StoreError> {
        let db = self.db.lock().unwrap();
        let changed = db.execute(
            "DELETE FROM devices WHERE endpoint_id = ?1",
            params![&endpoint_id[..]],
        )?;
        Ok(changed == 1)
    }

    /// All enrolled devices, sorted by name.
    pub fn list(&self) -> Result<Vec<Device>, StoreError> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT endpoint_id, name, routes FROM devices ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, routes) = row?;
            let endpoint_id: [u8; 32] = id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::BadId(id.len()))?;
            out.push(Device {
                endpoint_id,
                name,
                routes: split_routes(&routes),
            });
        }
        Ok(out)
    }

    /// Records an event. Never fails the caller: a full disk shouldn't block a login.
    pub fn audit(&self, endpoint_id: &[u8; 32], event: &str, detail: &str) {
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "INSERT INTO audit_log (ts, endpoint_id, event, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now(), &endpoint_id[..], event, detail],
        );
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn alg_name(alg: Alg) -> &'static str {
    match alg {
        Alg::Es256 => "es256",
        Alg::EdDsa => "eddsa",
    }
}

fn parse_alg(s: &str) -> Result<Alg, StoreError> {
    match s {
        "es256" => Ok(Alg::Es256),
        "eddsa" => Ok(Alg::EdDsa),
        other => Err(StoreError::UnknownAlg(other.to_string())),
    }
}

fn split_routes(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|r| !r.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAPTOP: [u8; 32] = [1; 32];
    const OTHER: [u8; 32] = [2; 32];

    fn web() -> Vec<String> {
        vec!["web".to_string()]
    }

    /// A fresh in-memory store with one laptop enrolled (EdDSA credential "cred-a").
    fn enrolled() -> Store {
        let s = Store::in_memory().unwrap();
        s.enroll(&LAPTOP, "laptop", &web(), b"cred-a", Alg::EdDsa, &[7; 32])
            .unwrap();
        s
    }

    #[test]
    fn enroll_then_lookup() {
        let s = enrolled();
        let d = s.device(&LAPTOP).unwrap().unwrap();
        assert_eq!(d.name, "laptop");
        assert_eq!(d.routes, vec!["web"]);

        let creds = s.credentials(&LAPTOP).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].0, b"cred-a");
        assert_eq!(creds[0].1.alg, Alg::EdDsa);
        assert_eq!(creds[0].1.sign_count, 0);
    }

    #[test]
    fn unknown_device_is_none() {
        let s = enrolled();
        assert!(s.device(&OTHER).unwrap().is_none());
        assert!(s.credentials(&OTHER).unwrap().is_empty());
    }

    #[test]
    fn backup_key() {
        let s = enrolled();
        // A second FIDO2 key from the same laptop, new credential
        s.enroll(&LAPTOP, "laptop", &web(), b"cred-b", Alg::Es256, &[8; 65])
            .unwrap();
        assert_eq!(s.credentials(&LAPTOP).unwrap().len(), 2);
    }

    #[test]
    fn remove_cascades() {
        let s = enrolled();
        assert!(s.remove_device(&LAPTOP).unwrap());
        assert!(s.device(&LAPTOP).unwrap().is_none());
        assert!(s.credentials(&LAPTOP).unwrap().is_empty()); // gone via ON DELETE CASCADE
        assert!(!s.remove_device(&LAPTOP).unwrap()); // nothing left to remove
    }

    #[test]
    fn counter_compare_and_swap() {
        let s = enrolled();
        assert!(s.bump_counter(b"cred-a", 0, 5).unwrap()); // stored 0 -> 5
        assert!(!s.bump_counter(b"cred-a", 0, 6).unwrap()); // stale: stored is 5, not 0
        assert_eq!(s.credentials(&LAPTOP).unwrap()[0].1.sign_count, 5);
    }

    #[test]
    fn duplicate_name_rejected() {
        let s = enrolled();
        let result = s.enroll(&OTHER, "laptop", &web(), b"cred-o", Alg::EdDsa, &[9; 32]);
        assert!(result.is_err()); // the schema's UNIQUE on name refuses it
    }

    #[test]
    fn list_is_sorted() {
        let s = enrolled();
        s.enroll(&OTHER, "desktop", &web(), b"cred-o", Alg::EdDsa, &[9; 32])
            .unwrap();
        let names: Vec<String> = s.list().unwrap().into_iter().map(|d| d.name).collect();
        assert_eq!(names, vec!["desktop", "laptop"]);
    }
}
