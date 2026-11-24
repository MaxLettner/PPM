//! mDNS discovery between two nodes on this machine (needs multicast on some interface).
use peerpass_core::crypto::KdfParams;
use peerpass_core::identity::Identity;
use peerpass_core::model::{Entry, DeviceInfo};
use peerpass_core::storage::Storage;
use peerpass_core::sync::discovery::Discovery;
use peerpass_core::sync::node::Node;
use peerpass_core::vault::Vault;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn discovered_peer_syncs() {
    let kdf = KdfParams { m_kib: 64, t: 1, p: 1 };
    let mk = |port| {
        let v = Arc::new(Mutex::new(Vault::new(Storage::open_in_memory().unwrap(), Identity::generate())));
        let n = Node::new(v, port, Box::new(|_, _| true), Box::new(|| {}));
        n.listen().unwrap();
        n
    };
    let a = mk(47901);
    let b = mk(47902);
    a.vault.lock().unwrap().create("m", "a", kdf).unwrap();
    let h = a.vault.lock().unwrap().db.header().unwrap().unwrap();
    {
        let mut bv = b.vault.lock().unwrap();
        bv.apply_header(h).unwrap();
        bv.unlock("m").unwrap();
    }
    let bpub = *b.vault.lock().unwrap().identity().public();
    let apub = *a.vault.lock().unwrap().identity().public();
    a.vault.lock().unwrap().add_device(DeviceInfo { pubkey: bpub, name: "b".into() }).unwrap();
    b.vault.lock().unwrap().add_device(DeviceInfo { pubkey: apub, name: "a".into() }).unwrap();
    let mut e = Entry::default();
    e.title = "x".into();
    a.vault.lock().unwrap().put(None, e).unwrap();
    let _da = Discovery::start(a.clone()).unwrap();
    let _db = Discovery::start(b.clone()).unwrap();
    for _ in 0..100 {
        if b.vault.lock().unwrap().list().unwrap().len() == 1 {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("not discovered");
}
