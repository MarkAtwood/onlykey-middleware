/// SQLite-backed certificate store shared between onlykey-vcard and onlykey-pkcs11.
///
/// Each certificate is keyed by a slot identifier string (e.g. `"piv-9A"`).
/// Supplementary key/value metadata can be attached to any slot.
///
/// The caller is responsible for wrapping [`Certstore`] in a `Mutex` when
/// shared across threads; the struct itself holds an unguarded [`Connection`].
use std::path::Path;

use rusqlite::{params, Connection};
use thiserror::Error;

/// Errors returned by [`Certstore`] operations.
#[derive(Debug, Error)]
pub enum CertstoreError {
    /// A rusqlite or SQLite-level error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A filesystem path could not be resolved.
    #[error("Path error: {0}")]
    Path(String),
    /// An I/O error while creating parent directories.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The supplied DER data is structurally invalid.
    #[error("invalid DER: {0}")]
    InvalidDer(String),
}

/// Validate that `data` begins with a well-formed DER SEQUENCE tag and length.
fn is_valid_der_sequence(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    if data[0] != 0x30 {
        return false;
    }
    if data[1] & 0x80 == 0 {
        let len = data[1] as usize;
        return data.len() >= 2 + len;
    }
    let num_bytes = (data[1] & 0x7F) as usize;
    if num_bytes == 0 || num_bytes > 4 || data.len() < 2 + num_bytes {
        return false;
    }
    let mut len: usize = 0;
    for i in 0..num_bytes {
        len = (len << 8) | data[2 + i] as usize;
    }
    data.len() >= 2 + num_bytes + len
}

/// An open handle to the certificate store database.
pub struct Certstore {
    conn: Connection,
}

impl Certstore {
    /// Open (or create) a certstore at `path`.
    ///
    /// Parent directories are created if they do not exist.
    /// WAL journal mode is enabled for safe concurrent access.
    pub fn open(path: &Path) -> Result<Self, CertstoreError> {
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;

        let conn = Connection::open(path)?;
        Self::apply_schema(&conn)?;
        check_schema_version(&conn)?;
        Ok(Certstore { conn })
    }

    /// Open the default certstore at `~/.local/share/onlykey/certs.db`.
    ///
    /// The XDG data directory is resolved via [`dirs::data_dir`].
    pub fn open_default() -> Result<Self, CertstoreError> {
        let base = dirs::data_dir()
            .ok_or_else(|| CertstoreError::Path("cannot determine data directory".into()))?;
        let path = base.join("onlykey").join("certs.db");
        Self::open(&path)
    }

    /// Retrieve the DER-encoded certificate for `slot`, or `None` if absent.
    pub fn get_cert(&self, slot: &str) -> Result<Option<Vec<u8>>, CertstoreError> {
        let mut stmt = self.conn.prepare("SELECT der FROM certs WHERE slot = ?1")?;
        let mut rows = stmt.query(params![slot])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Insert or replace the certificate for `slot`.
    pub fn put_cert(&self, slot: &str, der: &[u8], label: &str) -> Result<(), CertstoreError> {
        if !is_valid_der_sequence(der) {
            return Err(CertstoreError::InvalidDer(
                "outer SEQUENCE tag/length malformed".into(),
            ));
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO certs (slot, der, label) VALUES (?1, ?2, ?3)",
            params![slot, der, label],
        )?;
        Ok(())
    }

    /// List all stored certificates as `(slot, label)` pairs.
    pub fn list(&self) -> Result<Vec<(String, String)>, CertstoreError> {
        let mut stmt = self.conn.prepare("SELECT slot, label FROM certs")?;
        let rows = stmt.query_map(params![], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Get a metadata value for `slot` + `key`, or `None` if absent.
    pub fn get_metadata(&self, slot: &str, key: &str) -> Result<Option<String>, CertstoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM metadata WHERE slot = ?1 AND key = ?2")?;
        let mut rows = stmt.query(params![slot, key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Insert or replace a metadata value for `slot` + `key`.
    pub fn put_metadata(&self, slot: &str, key: &str, value: &str) -> Result<(), CertstoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (slot, key, value) VALUES (?1, ?2, ?3)",
            params![slot, key, value],
        )?;
        Ok(())
    }

    fn apply_schema(conn: &Connection) -> Result<(), CertstoreError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS certs (
                 slot  TEXT PRIMARY KEY,
                 der   BLOB NOT NULL,
                 label TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS metadata (
                 slot  TEXT NOT NULL,
                 key   TEXT NOT NULL,
                 value TEXT NOT NULL,
                 PRIMARY KEY (slot, key)
             );
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER NOT NULL
             );
             INSERT INTO schema_version (version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);",
        )?;
        Ok(())
    }
}

fn check_schema_version(conn: &Connection) -> Result<(), CertstoreError> {
    let v: i64 = conn.query_row("SELECT version FROM schema_version", [], |row| row.get(0))?;
    if v != 1 {
        return Err(CertstoreError::Sqlite(rusqlite::Error::InvalidQuery));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_store() -> Certstore {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS certs (
                 slot TEXT PRIMARY KEY,
                 der  BLOB NOT NULL,
                 label TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS metadata (
                 slot  TEXT NOT NULL,
                 key   TEXT NOT NULL,
                 value TEXT NOT NULL,
                 PRIMARY KEY (slot, key)
             );",
        )
        .unwrap();
        Certstore { conn }
    }

    #[test]
    fn put_and_get_cert() {
        let store = make_test_store();
        // Minimal valid DER: SEQUENCE (0x30) with zero-length content.
        let der = vec![0x30u8, 0x00];
        store.put_cert("piv-9A", &der, "My Cert").unwrap();
        let got = store.get_cert("piv-9A").unwrap().unwrap();
        assert_eq!(got, der);
    }

    #[test]
    fn get_cert_missing_returns_none() {
        let store = make_test_store();
        assert!(store.get_cert("piv-9A").unwrap().is_none());
    }

    #[test]
    fn list_returns_all_slots() {
        let store = make_test_store();
        store.put_cert("piv-9A", &[0x30, 0x00], "Cert A").unwrap();
        store.put_cert("piv-9C", &[0x30, 0x00], "Cert C").unwrap();
        let mut list = store.list().unwrap();
        list.sort();
        assert_eq!(
            list,
            vec![
                ("piv-9A".to_string(), "Cert A".to_string()),
                ("piv-9C".to_string(), "Cert C".to_string()),
            ]
        );
    }

    #[test]
    fn put_and_get_metadata() {
        let store = make_test_store();
        store
            .put_metadata("piv-9A", "fingerprint", "aabbccdd")
            .unwrap();
        let got = store
            .get_metadata("piv-9A", "fingerprint")
            .unwrap()
            .unwrap();
        assert_eq!(got, "aabbccdd");
    }

    #[test]
    fn metadata_missing_returns_none() {
        let store = make_test_store();
        assert!(store
            .get_metadata("piv-9A", "fingerprint")
            .unwrap()
            .is_none());
    }

    #[test]
    fn put_cert_updates_existing() {
        let store = make_test_store();
        // Two distinct minimal valid DER blobs to verify upsert replaces the first.
        store.put_cert("piv-9A", &[0x30, 0x00], "Old").unwrap();
        store
            .put_cert("piv-9A", &[0x30, 0x02, 0x00, 0x00], "New")
            .unwrap();
        let got = store.get_cert("piv-9A").unwrap().unwrap();
        assert_eq!(got, vec![0x30u8, 0x02, 0x00, 0x00]);
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1, "New");
    }

    #[test]
    fn open_default_uses_tempdir() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("onlykey").join("certs.db");
        let store = Certstore::open(&db_path).unwrap();
        store.put_cert("test-slot", &[0x30, 0x00], "Test").unwrap();
        let got = store.get_cert("test-slot").unwrap().unwrap();
        assert_eq!(got, vec![0x30u8, 0x00]);
    }
}
