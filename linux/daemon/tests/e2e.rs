//! Two real peerpassd processes on one machine (different ports, DBs and sockets):
//! create, pair over the socket API, sync, conflict, delete.
use peerpassd::Client;
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

struct D {
    child: Child,
    client: Client,
    port: u16,
}

impl Drop for D {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(dir: &Path, name: &str) -> D {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let sock = dir.join(format!("{name}.sock"));
    let child = Command::new(env!("CARGO_BIN_EXE_peerpassd"))
        .args(["--data-dir", dir.join(name).to_str().unwrap(), "--socket", sock.to_str().unwrap()])
        .args(["--port", &port.to_string(), "--no-mdns"])
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if let Ok(client) = Client::connect(&sock) {
            return D { child, client, port };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not start");
}

fn call(d: &mut D, m: &str, p: Value) -> Value {
    d.client.call(m, p).unwrap_or_else(|e| panic!("{m}: {e}"))
}

fn wait_for(d: &mut D, what: &str, f: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..200 {
        let s = call(d, "pair_status", Value::Null);
        if f(&s) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timeout waiting for {what}");
}

#[test]
fn two_daemons_pair_and_sync() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = spawn(dir.path(), "a");
    let mut b = spawn(dir.path(), "b");

    call(&mut a, "create", json!({ "password": "master pw", "device_name": "laptop" }));
    let id = call(&mut a, "put", json!({ "entry": {
        "title": "Mail", "username": "me", "password": "s3cret", "urls": ["https://mail.example.com"],
        "notes": "", "totp": null, "custom_fields": [], "updated_at": 0 } }));

    // Pair: the offer's addresses are rewritten to loopback for the test.
    let offer = call(&mut a, "pair_begin", Value::Null);
    let mut o = peerpass_core::sync::pairing::PairingOffer::from_text(offer["text"].as_str().unwrap()).unwrap();
    o.addrs = vec!["127.0.0.1".into()];
    assert_eq!(o.port, a.port);
    call(&mut b, "pair_join", json!({ "text": o.to_text(), "device_name": "desktop" }));
    let pending = wait_for(&mut a, "approval request", |s| !s["pending"].is_null());
    let code_a = pending["pending"]["code"].as_str().unwrap().to_string();
    assert_eq!(pending["pending"]["name"], "desktop");
    let joined = wait_for(&mut b, "join code", |s| !s["join"]["code"].is_null());
    assert_eq!(joined["join"]["code"].as_str().unwrap(), code_a, "both screens show the same code");
    call(&mut a, "pair_respond", json!({ "accept": true }));
    let done = wait_for(&mut b, "join done", |s| s["join"]["done"] == true);
    assert!(done["join"]["error"].is_null(), "{done}");

    // B needs the master password; then sync.
    assert!(b.client.call("list", Value::Null).is_err());
    call(&mut b, "unlock", json!({ "password": "master pw" }));
    let r = call(&mut b, "sync_now", Value::Null);
    assert_eq!(r[0]["ok"], true, "{r}");
    let list = call(&mut b, "list", Value::Null);
    assert_eq!(list[0]["title"], "Mail");
    let found = call(&mut b, "find", json!({ "url": "https://login.example.com/x" }));
    assert_eq!(found[0]["password"], "s3cret");

    // Conflict: both edit, sync, both see two siblings.
    for (d, pw) in [(&mut a, "from-a"), (&mut b, "from-b")] {
        call(d, "put", json!({ "id": id, "entry": {
            "title": "Mail", "username": "me", "password": pw, "urls": [], "notes": "",
            "totp": null, "custom_fields": [], "updated_at": 0 } }));
    }
    call(&mut b, "sync_now", Value::Null);
    for d in [&mut a, &mut b] {
        let it = call(d, "get", json!({ "id": id }));
        assert_eq!(it["siblings"].as_array().unwrap().len(), 2);
        assert_eq!(call(d, "status", Value::Null)["conflicts"], 1);
    }
    // Delete on A resolves (tombstone dominates both), B follows.
    call(&mut a, "delete", json!({ "id": id }));
    call(&mut b, "sync_now", Value::Null);
    assert_eq!(call(&mut b, "list", Value::Null), json!([]));

    // A sees B by name with a last sync time.
    let peers = call(&mut a, "peers", Value::Null);
    assert_eq!(peers[0]["name"], "desktop");
    assert!(!peers[0]["last_sync"].is_null());
}
