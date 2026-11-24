use peerpass_core::crypto::KdfParams;
use peerpass_core::identity::Identity;
use peerpass_core::model::Entry;
use peerpass_core::storage::Storage;
use peerpass_core::sync::exchange::{apply, build_index, missing_for};
use peerpass_core::sync::node::Node;
use peerpass_core::vault::Vault;
use proptest::prelude::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn kdf() -> KdfParams {
    KdfParams { m_kib: 64, t: 1, p: 1 }
}

fn entry(title: &str, pw: &str) -> Entry {
    let mut e = Entry::default();
    e.title = title.into();
    e.username = "alice@example.com".into();
    e.password = pw.into();
    e
}

/// Three vaults sharing one vault key (as after pairing + unlock).
fn three() -> Vec<Vault> {
    let mut a = Vault::new(Storage::open_in_memory().unwrap(), Identity::generate());
    a.create("pw", "a", kdf()).unwrap();
    let h = a.db.header().unwrap().unwrap();
    let mut out = vec![a];
    for n in ["b", "c"] {
        let mut v = Vault::new(Storage::open_in_memory().unwrap(), Identity::generate());
        v.apply_header(h.clone()).unwrap();
        v.db.set_meta("device_name", n.as_bytes()).unwrap();
        v.unlock("pw").unwrap();
        out.push(v);
    }
    out
}

/// In-process version of the exchange (same functions the TCP protocol uses).
fn sync_pair(a: &mut Vault, b: &mut Vault) {
    let ia = build_index(a).unwrap();
    let ib = build_index(b).unwrap();
    let (r, h) = missing_for(b, &ia).unwrap();
    apply(a, r, h).unwrap();
    let (r, h) = missing_for(a, &ib).unwrap();
    apply(b, r, h).unwrap();
}

fn pair_mut(vs: &mut [Vault], i: usize, j: usize) -> (&mut Vault, &mut Vault) {
    assert_ne!(i, j);
    if i < j {
        let (l, r) = vs.split_at_mut(j);
        (&mut l[i], &mut r[0])
    } else {
        let (l, r) = vs.split_at_mut(i);
        (&mut r[0], &mut l[j])
    }
}

#[derive(Debug, Clone)]
enum Op {
    Edit(usize, u128, u8),
    Delete(usize, u128),
    Sync(usize, usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..3usize, 1..5u128, any::<u8>()).prop_map(|(p, s, x)| Op::Edit(p, s, x)),
        (0..3usize, 1..5u128).prop_map(|(p, s)| Op::Delete(p, s)),
        (0..3usize, 0..3usize).prop_filter("distinct", |(a, b)| a != b).prop_map(|(a, b)| Op::Sync(a, b)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn three_peers_converge(ops in proptest::collection::vec(op(), 1..60)) {
        let mut vs = three();
        for o in &ops {
            match *o {
                Op::Edit(p, s, x) => { vs[p].put(Some(Uuid::from_u128(s)), entry(&format!("t{x}"), "pw")).unwrap(); }
                Op::Delete(p, s) => { let _ = vs[p].delete(&Uuid::from_u128(s)); }
                Op::Sync(a, b) => { let (x, y) = pair_mut(&mut vs, a, b); sync_pair(x, y); }
            }
        }
        for _ in 0..2 {
            for (a, b) in [(0, 1), (1, 2), (0, 2)] {
                let (x, y) = pair_mut(&mut vs, a, b);
                sync_pair(x, y);
            }
        }
        let norm = |v: &Vault| {
            let mut r = v.db.all_records().unwrap();
            r.sort_by_key(|x| (x.id, postcard::to_allocvec(&x.vv).unwrap()));
            r
        };
        let s0 = norm(&vs[0]);
        prop_assert_eq!(&s0, &norm(&vs[1]));
        prop_assert_eq!(&s0, &norm(&vs[2]));
        prop_assert_eq!(vs[0].db.header().unwrap(), vs[2].db.header().unwrap());
        // Every decrypted view is identical as well.
        let titles = |v: &Vault| v.list().unwrap().iter().map(|i| (i.id, i.siblings.len())).collect::<Vec<_>>();
        prop_assert_eq!(titles(&vs[0]), titles(&vs[1]));
    }
}

// ---------- over real TCP ----------

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn node(dir: &std::path::Path, name: &str, port: u16) -> Arc<Node> {
    let db = Storage::open(&dir.join(format!("{name}.db"))).unwrap();
    let v = Arc::new(Mutex::new(Vault::new(db, Identity::generate())));
    let n = Node::new(v, port, Box::new(|_, _| true), Box::new(|| {}));
    n.listen().unwrap();
    n
}

/// A creates a vault, B pairs with it through the text payload (addr forced to loopback).
fn paired(dir: &std::path::Path) -> (Arc<Node>, Arc<Node>) {
    let a = node(dir, "a", free_port());
    let b = node(dir, "b", free_port());
    a.vault.lock().unwrap().create("master", "laptop", kdf()).unwrap();
    let mut offer = a.begin_pairing().unwrap();
    offer.addrs = vec!["127.0.0.1".into()];
    let code = Mutex::new(String::new());
    let name = b.join(&offer.to_text(), "phone", &|c| *code.lock().unwrap() = c.to_string()).unwrap();
    assert_eq!(name, "laptop");
    assert_eq!(code.lock().unwrap().len(), 6);
    // Joined but not unlocked: the QR alone gives no access.
    assert!(b.vault.lock().unwrap().list().is_err());
    b.vault.lock().unwrap().unlock("master").unwrap();
    (a, b)
}

#[test]
fn pair_then_sync_both_ways_and_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = paired(dir.path());
    let id = a.vault.lock().unwrap().put(None, entry("Mail", "hunter2")).unwrap();
    let bp = b.vault.lock().unwrap().db.peers().unwrap();
    assert_eq!(bp.len(), 1);
    let st = b.sync_peer(&bp[0]).unwrap();
    assert!(st.applied > 0);
    assert_eq!(b.vault.lock().unwrap().get(&id).unwrap().siblings[0].entry.as_ref().unwrap().password, "hunter2");
    // B's own device record reached A, and A learned B's address.
    assert_eq!(a.vault.lock().unwrap().devices().unwrap().len(), 2);
    // A records last_sync right after its final Done; give its thread a moment.
    let mut ok = false;
    for _ in 0..50 {
        if a.vault.lock().unwrap().db.peers().unwrap()[0].last_sync.is_some() { ok = true; break; }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(ok);

    // Concurrent edits -> conflict on both sides.
    a.vault.lock().unwrap().put(Some(id), entry("Mail", "from-a")).unwrap();
    b.vault.lock().unwrap().put(Some(id), entry("Mail", "from-b")).unwrap();
    // Sync while A is locked: still works, only blobs move.
    a.vault.lock().unwrap().lock();
    b.sync_all().into_iter().for_each(|(_, r)| { r.unwrap(); });
    a.vault.lock().unwrap().unlock("master").unwrap();
    assert_eq!(a.vault.lock().unwrap().get(&id).unwrap().siblings.len(), 2);
    assert_eq!(b.vault.lock().unwrap().conflict_count().unwrap(), 1);
    // Resolving on A collapses on both.
    a.vault.lock().unwrap().put(Some(id), entry("Mail", "merged")).unwrap();
    b.sync_all();
    assert_eq!(b.vault.lock().unwrap().get(&id).unwrap().siblings.len(), 1);

    // Password change propagates through the header.
    a.vault.lock().unwrap().change_password("new-master", kdf()).unwrap();
    b.sync_all();
    let mut bv = b.vault.lock().unwrap();
    bv.lock();
    assert!(bv.unlock("master").is_err());
    bv.unlock("new-master").unwrap();
}

#[test]
fn unknown_peer_fails_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _b) = paired(dir.path());
    let c = node(dir.path(), "c", free_port());
    // C pretends A is its peer, but A does not know C.
    let (apub, aport) = (*a.vault.lock().unwrap().identity().public(), a.port);
    let peer = peerpass_core::storage::Peer {
        device_id: peerpass_core::model::device_id_from_pubkey(&apub),
        pubkey: apub,
        name: "a".into(),
        last_addr: Some(format!("127.0.0.1:{aport}")),
        last_sync: None,
    };
    assert!(c.sync_peer(&peer).is_err());
    // Expired/absent pairing session also refuses pairing.
    let mut offer = {
        let v = a.vault.lock().unwrap();
        peerpass_core::sync::pairing::create_offer(&v, vec!["127.0.0.1".into()], aport).unwrap().0
    };
    offer.addrs = vec!["127.0.0.1".into()];
    assert!(c.join(&offer.to_text(), "evil", &|_| {}).is_err());
}

#[test]
fn rejected_pairing_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let db = Storage::open(&dir.path().join("a.db")).unwrap();
    let v = Arc::new(Mutex::new(Vault::new(db, Identity::generate())));
    let a = Node::new(v, free_port(), Box::new(|_, _| false), Box::new(|| {}));
    a.listen().unwrap();
    a.vault.lock().unwrap().create("m", "laptop", kdf()).unwrap();
    let b = node(dir.path(), "b", free_port());
    let mut offer = a.begin_pairing().unwrap();
    offer.addrs = vec!["127.0.0.1".into()];
    assert!(b.join(&offer.to_text(), "phone", &|_| {}).is_err());
    assert!(a.vault.lock().unwrap().db.peers().unwrap().is_empty());
    assert!(!b.vault.lock().unwrap().has_vault().unwrap());
}

/// Captures every byte of a sync session through a forwarding proxy and asserts that no
/// secret (title, username, password, notes) appears on the wire.
#[test]
fn no_plaintext_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = paired(dir.path());
    let mut e = entry("VerySecretTitleXYZ", "CorrectHorseBatteryStaple");
    e.notes = "NotesPlaintextMarker".into();
    a.vault.lock().unwrap().put(None, e).unwrap();
    b.vault.lock().unwrap().put(None, entry("OtherSecretTitleQQ", "Tr0ub4dor&3")).unwrap();

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let paddr = proxy.local_addr().unwrap();
    let target = format!("127.0.0.1:{}", a.port);
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let cap = captured.clone();
    let h = std::thread::spawn(move || {
        let (client, _) = proxy.accept().unwrap();
        let server = TcpStream::connect(target).unwrap();
        let pump = |mut from: TcpStream, mut to: TcpStream, cap: Arc<Mutex<Vec<u8>>>| {
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(n) = from.read(&mut buf) {
                    if n == 0 { break; }
                    cap.lock().unwrap().extend_from_slice(&buf[..n]);
                    if to.write_all(&buf[..n]).is_err() { break; }
                }
                let _ = to.shutdown(std::net::Shutdown::Write);
            })
        };
        let t1 = pump(client.try_clone().unwrap(), server.try_clone().unwrap(), cap.clone());
        let t2 = pump(server, client, cap);
        t1.join().unwrap();
        t2.join().unwrap();
    });
    let mut peer = b.vault.lock().unwrap().db.peers().unwrap().remove(0);
    peer.last_addr = Some(paddr.to_string());
    let st = b.sync_peer(&peer).unwrap();
    assert!(st.sent > 0 && st.received > 0);
    h.join().unwrap();
    let bytes = captured.lock().unwrap().clone();
    assert!(bytes.len() > 200);
    for needle in ["VerySecretTitleXYZ", "CorrectHorseBatteryStaple", "NotesPlaintextMarker", "OtherSecretTitleQQ", "Tr0ub4dor&3", "alice@example.com", "laptop", "phone"] {
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} leaked");
    }
    // Both sides converged through the proxy.
    assert_eq!(a.vault.lock().unwrap().list().unwrap().len(), 2);
    assert_eq!(b.vault.lock().unwrap().list().unwrap().len(), 2);
}
