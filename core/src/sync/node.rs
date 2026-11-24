//! A running sync node: TCP listener, outgoing syncs, pairing state.
//! Shared by the Linux daemon and the Android app.
use super::exchange::{self, SyncStats};
use super::pairing::{self, PairingOffer, PairingSession};
use super::transport::{read_preamble, NoiseStream, MODE_PAIR};
use crate::model::DeviceId;
use crate::storage::Peer;
use crate::vault::{now, Vault};
use crate::{Error, Result};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub type Approver = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;
pub type Notify = Box<dyn Fn() + Send + Sync>;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Node {
    pub vault: Arc<Mutex<Vault>>,
    pub port: u16,
    discovered: Mutex<HashMap<DeviceId, SocketAddr>>,
    pairing: Mutex<Option<PairingSession>>,
    approver: Approver,
    on_change: Notify,
}

impl Node {
    /// `approver(name, code)` is asked on incoming pairing; `on_change` fires after a sync
    /// or pairing changed local state.
    pub fn new(vault: Arc<Mutex<Vault>>, port: u16, approver: Approver, on_change: Notify) -> Arc<Self> {
        Arc::new(Self {
            vault,
            port,
            discovered: Mutex::new(HashMap::new()),
            pairing: Mutex::new(None),
            approver,
            on_change,
        })
    }

    /// Binds the listener and serves connections on background threads.
    pub fn listen(self: &Arc<Self>) -> Result<TcpListener> {
        let l = TcpListener::bind(("0.0.0.0", self.port))?;
        let l2 = l.try_clone()?;
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            for s in l2.incoming().flatten() {
                let me = Arc::clone(&me);
                std::thread::spawn(move || {
                    if let Err(e) = me.handle(s) {
                        log(&format!("incoming connection failed: {e}"));
                    }
                });
            }
        });
        Ok(l)
    }

    fn handle(&self, mut s: TcpStream) -> Result<()> {
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))?;
        let (mode, dev) = read_preamble(&mut s)?;
        if mode == MODE_PAIR {
            s.set_read_timeout(Some(Duration::from_secs(180)))?;
            if pairing::handle_incoming(&self.vault, s, &self.pairing, &*self.approver)?.is_some() {
                (self.on_change)();
            }
            return Ok(());
        }
        let d = dev.unwrap();
        let (peer, secret) = {
            let v = self.vault.lock().unwrap();
            // Unknown device ids are dropped before any handshake.
            (v.db.peer(&d)?.ok_or_else(|| Error::Protocol("unknown peer".into()))?, Zeroizing::new(*v.identity().secret()))
        };
        let ip = s.peer_addr()?.ip();
        let mut ns = NoiseStream::accept_kk(s, &secret, &peer.pubkey)?;
        let (st, port) = exchange::run_responder(&self.vault, &mut ns, self.port)?;
        self.after_sync(&peer.device_id, SocketAddr::new(ip, port), st)?;
        Ok(())
    }

    fn after_sync(&self, d: &DeviceId, addr: SocketAddr, st: SyncStats) -> Result<()> {
        {
            let v = self.vault.lock().unwrap();
            v.db.set_peer_addr(d, &addr.to_string())?;
            v.db.set_peer_synced(d, now())?;
        }
        if st.applied > 0 {
            (self.on_change)();
        }
        Ok(())
    }

    /// Records an mDNS sighting. Returns the peer if the device id is a paired peer.
    pub fn note_discovered(&self, d: DeviceId, addr: SocketAddr) -> Option<Peer> {
        let peer = self.vault.lock().unwrap().db.peer(&d).ok().flatten()?;
        self.discovered.lock().unwrap().insert(d, addr);
        Some(peer)
    }

    /// Syncs with one peer: tries the mDNS address, then its last known address.
    pub fn sync_peer(&self, peer: &Peer) -> Result<SyncStats> {
        let mut cands: Vec<SocketAddr> = Vec::new();
        if let Some(a) = self.discovered.lock().unwrap().get(&peer.device_id) {
            cands.push(*a);
        }
        if let Some(a) = peer.last_addr.as_deref().and_then(|a| a.parse().ok())
            && !cands.contains(&a) {
                cands.push(a);
            }
        let (secret, my_id) = {
            let v = self.vault.lock().unwrap();
            (Zeroizing::new(*v.identity().secret()), v.device_id())
        };
        let mut last = Error::Protocol("no known address".into());
        for addr in cands {
            let s = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(s) => s,
                Err(e) => {
                    last = e.into();
                    continue;
                }
            };
            s.set_read_timeout(Some(IO_TIMEOUT))?;
            s.set_write_timeout(Some(IO_TIMEOUT))?;
            let mut ns = NoiseStream::connect_kk(s, &secret, &my_id, &peer.pubkey)?;
            let (st, _) = exchange::run_initiator(&self.vault, &mut ns, self.port)?;
            self.after_sync(&peer.device_id, addr, st)?;
            return Ok(st);
        }
        Err(last)
    }

    /// Syncs with every paired peer; errors are per peer.
    pub fn sync_all(&self) -> Vec<(Peer, Result<SyncStats>)> {
        let peers = self.vault.lock().unwrap().db.peers().unwrap_or_default();
        peers.into_iter().map(|p| {
            let r = self.sync_peer(&p);
            (p, r)
        }).collect()
    }

    /// Starts accepting one pairing for 5 minutes. Requires an unlocked vault.
    pub fn begin_pairing(&self) -> Result<PairingOffer> {
        let (offer, sess) = pairing::create_offer(&self.vault.lock().unwrap(), pairing::local_ipv4_addrs(), self.port)?;
        *self.pairing.lock().unwrap() = Some(sess);
        Ok(offer)
    }

    pub fn cancel_pairing(&self) {
        *self.pairing.lock().unwrap() = None;
    }

    /// New device side of pairing.
    pub fn join(&self, offer_text: &str, my_name: &str, on_code: &dyn Fn(&str)) -> Result<String> {
        let offer = PairingOffer::from_text(offer_text)?;
        let name = pairing::join(&self.vault, &offer, my_name, self.port, on_code)?;
        (self.on_change)();
        Ok(name)
    }
}

/// Minimal logging to stderr. Never pass secrets here.
pub fn log(msg: &str) {
    eprintln!("[peerpass] {msg}");
}
