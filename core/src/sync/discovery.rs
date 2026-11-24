//! mDNS/DNS-SD discovery: advertises `_peerpass._tcp` with TXT v=1,id=<device_id hex>
//! and syncs with paired peers when they appear.
use super::node::{log, Node};
use super::SERVICE_TYPE;
use crate::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub struct Discovery {
    daemon: ServiceDaemon,
}

fn mdns_err(e: mdns_sd::Error) -> crate::Error {
    crate::Error::Protocol(format!("mdns: {e}"))
}

impl Discovery {
    pub fn start(node: Arc<Node>) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(mdns_err)?;
        let me = node.vault.lock().unwrap().device_id();
        let id = hex::encode(me);
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &id,
            &format!("peerpass-{id}.local."),
            "",
            node.port,
            &[("v", "1"), ("id", id.as_str())][..],
        )
        .map_err(mdns_err)?
        .enable_addr_auto();
        daemon.register(info).map_err(mdns_err)?;
        let rx = daemon.browse(SERVICE_TYPE).map_err(mdns_err)?;
        std::thread::spawn(move || {
            while let Ok(ev) = rx.recv() {
                let ServiceEvent::ServiceResolved(info) = ev else { continue };
                if info.get_property_val_str("v") != Some("1") {
                    continue;
                }
                let Some(d) = info
                    .get_property_val_str("id")
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                else {
                    continue;
                };
                if d == me {
                    continue;
                }
                let Some(ip) = info.get_addresses_v4().into_iter().next() else { continue };
                let addr = SocketAddr::new(IpAddr::V4(ip), info.get_port());
                // Only paired device ids are ever contacted.
                if let Some(peer) = node.note_discovered(d, addr) {
                    if let Err(e) = node.sync_peer(&peer) {
                        log(&format!("sync with {} failed: {e}", peer.name));
                    }
                }
            }
        });
        Ok(Self { daemon })
    }

    pub fn stop(&self) {
        let _ = self.daemon.shutdown();
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.stop();
    }
}
