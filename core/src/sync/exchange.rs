//! State-based exchange. Only opaque K_v-encrypted records and version vectors move,
//! so sync works while the vault is locked.
use super::transport::NoiseStream;
use super::PROTOCOL_VERSION;
use crate::model::{Record, VaultHeader, VersionVector};
use crate::vault::Vault;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Index {
    pub entries: Vec<(Uuid, Vec<VersionVector>)>,
    pub header_vv: Option<VersionVector>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Msg {
    Hello { version: u32, port: u16, vault_id: Option<Uuid> },
    Index(Index),
    Update { records: Vec<Record>, header: Option<VaultHeader> },
    Done,
    PairRequest { name: String, port: u16 },
    PairAccept { name: String, header: VaultHeader },
    PairReject,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncStats {
    pub sent: usize,
    pub received: usize,
    /// Records or header that changed local state.
    pub applied: usize,
}

pub fn build_index(v: &Vault) -> Result<Index> {
    let mut map: Vec<(Uuid, Vec<VersionVector>)> = Vec::new();
    for r in v.db.all_records()? {
        match map.last_mut() {
            Some((id, vvs)) if *id == r.id => vvs.push(r.vv),
            _ => map.push((r.id, vec![r.vv])),
        }
    }
    Ok(Index { entries: map, header_vv: v.db.header()?.map(|h| h.vv) })
}

/// Records (and header) the remote lacks or that are not dominated by its siblings.
pub fn missing_for(v: &Vault, remote: &Index) -> Result<(Vec<Record>, Option<VaultHeader>)> {
    let rmap: HashMap<&Uuid, &Vec<VersionVector>> = remote.entries.iter().map(|(i, v)| (i, v)).collect();
    let recs = v
        .db
        .all_records()?
        .into_iter()
        .filter(|r| !rmap.get(&r.id).is_some_and(|vvs| vvs.iter().any(|rv| rv.ge(&r.vv))))
        .collect();
    let header = v.db.header()?.filter(|h| !remote.header_vv.as_ref().is_some_and(|rv| rv.ge(&h.vv)));
    Ok((recs, header))
}

/// Applies incoming records/header with the merge rule. Returns how many changed state.
pub fn apply(v: &mut Vault, records: Vec<Record>, header: Option<VaultHeader>) -> Result<usize> {
    let mut n = 0;
    if let Some(h) = header {
        n += v.apply_header(h)? as usize;
    }
    for r in records {
        n += v.db.apply_incoming(r)? as usize;
    }
    if n > 0 && v.is_unlocked() {
        v.refresh_peers()?;
    }
    Ok(n)
}

fn hello(v: &Vault, port: u16) -> Result<Msg> {
    Ok(Msg::Hello { version: PROTOCOL_VERSION, port, vault_id: v.db.header()?.map(|h| h.vault_id) })
}

/// Checks the peer's Hello; returns its listen port.
fn check_hello(v: &Vault, m: Msg) -> Result<u16> {
    match m {
        Msg::Hello { version, port, vault_id } => {
            if version != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!("unsupported protocol version {version}")));
            }
            let mine = v.db.header()?.map(|h| h.vault_id);
            if let (Some(a), Some(b)) = (mine, vault_id) {
                if a != b {
                    return Err(Error::Protocol("peer belongs to another vault".into()));
                }
            }
            Ok(port)
        }
        _ => Err(Error::Protocol("expected Hello".into())),
    }
}

fn recv_index(ns: &mut NoiseStream) -> Result<Index> {
    match ns.recv()? {
        Msg::Index(i) => Ok(i),
        _ => Err(Error::Protocol("expected Index".into())),
    }
}

fn recv_update(ns: &mut NoiseStream) -> Result<(Vec<Record>, Option<VaultHeader>)> {
    let u = match ns.recv()? {
        Msg::Update { records, header } => (records, header),
        _ => return Err(Error::Protocol("expected Update".into())),
    };
    match ns.recv()? {
        Msg::Done => Ok(u),
        _ => Err(Error::Protocol("expected Done".into())),
    }
}

/// Initiator side. Returns stats and the peer's listen port.
pub fn run_initiator(vault: &Mutex<Vault>, ns: &mut NoiseStream, my_port: u16) -> Result<(SyncStats, u16)> {
    let (h, idx) = {
        let v = vault.lock().unwrap();
        (hello(&v, my_port)?, build_index(&v)?)
    };
    ns.send(&h)?;
    ns.send(&Msg::Index(idx))?;
    let hello_r: Msg = ns.recv()?;
    let port = check_hello(&vault.lock().unwrap(), hello_r)?;
    let ridx = recv_index(ns)?;
    let (recs, hdr) = recv_update(ns)?;
    let mut st = SyncStats { received: recs.len() + hdr.is_some() as usize, ..Default::default() };
    let (out, out_h) = {
        let mut v = vault.lock().unwrap();
        st.applied = apply(&mut v, recs, hdr)?;
        missing_for(&v, &ridx)?
    };
    st.sent = out.len() + out_h.is_some() as usize;
    ns.send(&Msg::Update { records: out, header: out_h })?;
    ns.send(&Msg::Done)?;
    // Final Done: the responder has applied our update.
    match ns.recv()? {
        Msg::Done => Ok((st, port)),
        _ => Err(Error::Protocol("expected Done".into())),
    }
}

/// Responder side. Returns stats and the peer's listen port.
pub fn run_responder(vault: &Mutex<Vault>, ns: &mut NoiseStream, my_port: u16) -> Result<(SyncStats, u16)> {
    let hello_i: Msg = ns.recv()?;
    let iidx = recv_index(ns)?;
    let (port, h, idx, out, out_h) = {
        let v = vault.lock().unwrap();
        let port = check_hello(&v, hello_i)?;
        let (out, out_h) = missing_for(&v, &iidx)?;
        (port, hello(&v, my_port)?, build_index(&v)?, out, out_h)
    };
    let mut st = SyncStats { sent: out.len() + out_h.is_some() as usize, ..Default::default() };
    ns.send(&h)?;
    ns.send(&Msg::Index(idx))?;
    ns.send(&Msg::Update { records: out, header: out_h })?;
    ns.send(&Msg::Done)?;
    let (recs, hdr) = recv_update(ns)?;
    st.received = recs.len() + hdr.is_some() as usize;
    st.applied = apply(&mut vault.lock().unwrap(), recs, hdr)?;
    ns.send(&Msg::Done)?;
    Ok((st, port))
}
