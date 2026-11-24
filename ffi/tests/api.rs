//! Exercises the Kotlin-facing API on the host: two app instances pair and sync,
//! autofill matching by domain and package, biometric key path, conflicts.
use peerpass_ffi::*;
use std::time::Duration;

fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn app(dir: &std::path::Path, n: &str) -> std::sync::Arc<PeerPass> {
    PeerPass::new(dir.join(format!("{n}.db")).to_string_lossy().into(), generate_identity(), port()).unwrap()
}

fn entry(title: &str, urls: &[&str]) -> EntryData {
    EntryData {
        title: title.into(),
        username: "me".into(),
        password: "pw-".to_string() + title,
        urls: urls.iter().map(|s| s.to_string()).collect(),
        notes: String::new(),
        totp: None,
        custom_fields: vec![],
        updated_at: 0,
    }
}

fn wait(f: impl Fn() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timeout");
}

#[test]
fn two_apps_pair_sync_autofill() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (app(dir.path(), "a"), app(dir.path(), "b"));
    a.create_vault("master-pw".into(), "phone".into()).unwrap();
    a.start_network().unwrap();
    b.start_network().unwrap();
    a.put(None, entry("Shop", &["https://www.shop.example.co.uk/login"])).unwrap();
    a.put(None, entry("App", &["androidapp://com.example.app"])).unwrap();

    // Pair B with A (address rewritten to loopback for the test).
    let mut o = peerpass_core::sync::pairing::PairingOffer::from_text(&a.pair_begin().unwrap()).unwrap();
    o.addrs = vec!["127.0.0.1".into()];
    b.pair_join(o.to_text(), "laptop".into());
    wait(|| a.pair_status().pending_code.is_some());
    assert_eq!(a.pair_status().pending_code, b.pair_status().join_code);
    a.pair_respond(true);
    wait(|| b.pair_status().join_done);
    assert!(b.pair_status().join_error.is_none());
    assert!(matches!(b.unlock("wrong".into()), Err(PpError::WrongPassword)));
    b.unlock("master-pw".into()).unwrap();
    assert!(b.sync_all()[0].ok);
    assert_eq!(b.list().unwrap().len(), 2);

    // Autofill: web domain via eTLD+1, apps via androidapp:// package URLs.
    let c = b.find_for_autofill(Some("shop.example.co.uk".into()), None).unwrap();
    assert_eq!((c.len(), c[0].password.as_str()), (1, "pw-Shop"));
    assert_eq!(b.find_for_autofill(None, Some("com.example.app".into())).unwrap().len(), 1);
    assert!(b.find_for_autofill(Some("example2.co.uk".into()), None).unwrap().is_empty());

    // Conflict shows every version, labelled.
    let id = c[0].id.clone();
    a.put(Some(id.clone()), entry("Shop", &["https://shop.example.co.uk"])).unwrap();
    b.put(Some(id.clone()), entry("Shop", &["https://shop.example.co.uk"])).unwrap();
    b.sync_all();
    let c = b.find_for_autofill(Some("shop.example.co.uk".into()), None).unwrap();
    assert_eq!(c.len(), 2);
    assert!(c[0].label.starts_with("version 1 of 2"));
    assert_eq!(a.conflict_count().unwrap(), 1);

    // Biometric path: export K_v, lock, unlock with it.
    let k = b.export_key().unwrap();
    let fp = b.header_fingerprint().unwrap();
    b.lock();
    b.unlock_with_key(k).unwrap();
    b.change_password("master-pw".into(), "new-pw-123".into()).unwrap();
    assert_ne!(fp, b.header_fingerprint().unwrap());

    // Background sync job (short) still works and returns per-peer results.
    let r = a.background_sync(1);
    assert!(r.iter().all(|x| x.ok), "{:?}", r.iter().map(|x| x.error.clone()).collect::<Vec<_>>());
    assert_eq!(a.header_fingerprint().unwrap(), b.header_fingerprint().unwrap());
}

#[test]
fn import_and_generator() {
    let dir = tempfile::tempdir().unwrap();
    let a = app(dir.path(), "a");
    a.create_vault("pw-12345".into(), "x".into()).unwrap();
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/tests/fixtures/keepass4.kdbx")).unwrap();
    let r = a.import_data("kdbx".into(), data, "fixture-pw".into()).unwrap();
    assert_eq!((r.imported, r.skipped), (2, 1));
    assert_eq!(generate_password(12, true, false, true, false).unwrap().len(), 12);
    assert_eq!(etld1("https://a.b.github.io/x".into()).as_deref(), Some("b.github.io"));
}
