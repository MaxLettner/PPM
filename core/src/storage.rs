//! SQLite storage. Holds only encrypted blobs, version vectors and peer metadata.
use crate::model::{merge_sibling, DeviceId, Record, RecordKind, VaultHeader, VersionVector};
use crate::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use uuid::Uuid;

pub struct Storage {
    conn: Connection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device_id: DeviceId,
    pub pubkey: [u8; 32],
    pub name: String,
    pub last_addr: Option<String>,
    pub last_sync: Option<i64>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries(
  id BLOB NOT NULL, kind INTEGER NOT NULL, vv BLOB NOT NULL,
  deleted INTEGER NOT NULL, blob BLOB NOT NULL, PRIMARY KEY(id, vv));
CREATE TABLE IF NOT EXISTS peers(
  device_id BLOB PRIMARY KEY, pubkey BLOB NOT NULL, name TEXT NOT NULL,
  last_addr TEXT, last_sync INTEGER);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
";

fn enc_vv(vv: &VersionVector) -> Vec<u8> {
    postcard::to_allocvec(vv).expect("vv encodes")
}

fn row_to_record(r: &rusqlite::Row) -> rusqlite::Result<(Vec<u8>, u8, Vec<u8>, bool, Vec<u8>)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn decode_record(t: (Vec<u8>, u8, Vec<u8>, bool, Vec<u8>)) -> Result<Record> {
    let (id, kind, vv, deleted, blob) = t;
    Ok(Record {
        id: Uuid::from_slice(&id).map_err(|e| Error::Invalid(e.to_string()))?,
        kind: RecordKind::from_u8(kind).ok_or_else(|| Error::Invalid("record kind".into()))?,
        vv: postcard::from_bytes(&vv)?,
        deleted,
        blob,
    })
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // ---- records ----

    pub fn siblings(&self, id: &Uuid) -> Result<Vec<Record>> {
        let mut st = self.conn.prepare_cached("SELECT id, kind, vv, deleted, blob FROM entries WHERE id=?1")?;
        let rows = st.query_map([id.as_bytes().as_slice()], row_to_record)?;
        rows.map(|r| decode_record(r?)).collect()
    }

    pub fn all_records(&self) -> Result<Vec<Record>> {
        let mut st = self.conn.prepare_cached("SELECT id, kind, vv, deleted, blob FROM entries ORDER BY id")?;
        let rows = st.query_map([], row_to_record)?;
        rows.map(|r| decode_record(r?)).collect()
    }

    pub fn records_of_kind(&self, kind: RecordKind) -> Result<Vec<Record>> {
        let mut st =
            self.conn.prepare_cached("SELECT id, kind, vv, deleted, blob FROM entries WHERE kind=?1 ORDER BY id")?;
        let rows = st.query_map([kind as u8], row_to_record)?;
        rows.map(|r| decode_record(r?)).collect()
    }

    /// Replaces all siblings of `id` with `recs` atomically.
    pub fn replace_siblings(&mut self, id: &Uuid, recs: &[Record]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM entries WHERE id=?1", [id.as_bytes().as_slice()])?;
        for r in recs {
            tx.execute(
                "INSERT INTO entries(id, kind, vv, deleted, blob) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![r.id.as_bytes().as_slice(), r.kind as u8, enc_vv(&r.vv), r.deleted, r.blob],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Applies an incoming sibling with the merge rule. Returns true if anything changed.
    pub fn apply_incoming(&mut self, r: Record) -> Result<bool> {
        let id = r.id;
        let mut local = self.siblings(&id)?;
        if let Some(l) = local.first() {
            if l.kind != r.kind {
                return Err(Error::Protocol("record kind mismatch".into()));
            }
        }
        if !merge_sibling(&mut local, r) {
            return Ok(false);
        }
        self.replace_siblings(&id, &local)?;
        Ok(true)
    }

    // ---- meta ----

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn header(&self) -> Result<Option<VaultHeader>> {
        match self.get_meta("header")? {
            Some(b) => Ok(Some(postcard::from_bytes(&b)?)),
            None => Ok(None),
        }
    }

    pub fn set_header(&self, h: &VaultHeader) -> Result<()> {
        self.set_meta("header", &postcard::to_allocvec(h)?)
    }

    // ---- peers ----

    pub fn peers(&self) -> Result<Vec<Peer>> {
        let mut st = self.conn.prepare_cached("SELECT device_id, pubkey, name, last_addr, last_sync FROM peers")?;
        let rows = st.query_map([], |r| {
            let d: Vec<u8> = r.get(0)?;
            let k: Vec<u8> = r.get(1)?;
            Ok((d, k, r.get::<_, String>(2)?, r.get(3)?, r.get(4)?))
        })?;
        rows.map(|r| {
            let (d, k, name, last_addr, last_sync) = r?;
            Ok(Peer {
                device_id: d.try_into().map_err(|_| Error::Invalid("device_id".into()))?,
                pubkey: k.try_into().map_err(|_| Error::Invalid("pubkey".into()))?,
                name,
                last_addr,
                last_sync,
            })
        })
        .collect()
    }

    pub fn peer(&self, d: &DeviceId) -> Result<Option<Peer>> {
        Ok(self.peers()?.into_iter().find(|p| &p.device_id == d))
    }

    /// Inserts or updates pubkey/name, keeping last_addr/last_sync.
    pub fn upsert_peer(&self, d: &DeviceId, pubkey: &[u8; 32], name: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO peers(device_id, pubkey, name) VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id) DO UPDATE SET pubkey=excluded.pubkey, name=excluded.name",
            params![d.as_slice(), pubkey.as_slice(), name],
        )?;
        Ok(())
    }

    pub fn remove_peer(&self, d: &DeviceId) -> Result<()> {
        self.conn.execute("DELETE FROM peers WHERE device_id=?1", [d.as_slice()])?;
        Ok(())
    }

    pub fn set_peer_addr(&self, d: &DeviceId, addr: &str) -> Result<()> {
        self.conn.execute("UPDATE peers SET last_addr=?2 WHERE device_id=?1", params![d.as_slice(), addr])?;
        Ok(())
    }

    pub fn set_peer_synced(&self, d: &DeviceId, ts: i64) -> Result<()> {
        self.conn.execute("UPDATE peers SET last_sync=?2 WHERE device_id=?1", params![d.as_slice(), ts])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_peers() {
        let mut s = Storage::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let mut vv = VersionVector::default();
        vv.increment([1; 8]);
        let r = Record { id, kind: RecordKind::Entry, vv: vv.clone(), deleted: false, blob: vec![1, 2] };
        assert!(s.apply_incoming(r.clone()).unwrap());
        assert!(!s.apply_incoming(r.clone()).unwrap());
        assert_eq!(s.siblings(&id).unwrap(), vec![r]);

        s.upsert_peer(&[2; 8], &[3; 32], "phone").unwrap();
        s.set_peer_addr(&[2; 8], "10.0.0.2:47823").unwrap();
        s.upsert_peer(&[2; 8], &[3; 32], "phone2").unwrap();
        let p = s.peer(&[2; 8]).unwrap().unwrap();
        assert_eq!(p.name, "phone2");
        assert_eq!(p.last_addr.as_deref(), Some("10.0.0.2:47823"));
        s.remove_peer(&[2; 8]).unwrap();
        assert!(s.peers().unwrap().is_empty());
    }
}
