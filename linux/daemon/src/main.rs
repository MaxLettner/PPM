//! peerpassd: the only process that touches the vault DB and keys on Linux.
use peerpass_core::crypto::KdfParams;
use peerpass_core::domain;
use peerpass_core::generator::{self, GenOptions};
use peerpass_core::import;
use peerpass_core::totp::Totp;
use peerpass_core::identity::Identity;
use peerpass_core::model::Entry;
use peerpass_core::storage::Storage;
use peerpass_core::sync::discovery::Discovery;
use peerpass_core::sync::node::{log, Node};
use peerpass_core::sync::DEFAULT_PORT;
use peerpass_core::vault::{EntryItem, Vault};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

const SYNC_INTERVAL: Duration = Duration::from_secs(300);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_AUTO_LOCK: u64 = 300;

#[derive(Default)]
struct Approval {
    name: String,
    code: String,
    decision: Option<bool>,
}

#[derive(Default, Clone)]
struct JoinState {
    code: Option<String>,
    done: bool,
    error: Option<String>,
    peer: Option<String>,
}

#[derive(Default)]
struct Shared {
    rev: AtomicU64,
    approval: Mutex<Option<Approval>>,
    cv: Condvar,
}

struct Daemon {
    node: Arc<Node>,
    shared: Arc<Shared>,
    last_activity: Mutex<Instant>,
    join: Arc<Mutex<Option<JoinState>>>,
    sync_tx: Mutex<Sender<()>>,
}

struct Args {
    data_dir: PathBuf,
    socket: PathBuf,
    port: u16,
    mdns: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        data_dir: peerpassd::paths::data_dir(),
        socket: peerpassd::paths::socket_path(),
        port: DEFAULT_PORT,
        mdns: true,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        match k.as_str() {
            "--data-dir" => a.data_dir = it.next().expect("--data-dir DIR").into(),
            "--socket" => a.socket = it.next().expect("--socket PATH").into(),
            "--port" => a.port = it.next().and_then(|p| p.parse().ok()).expect("--port N"),
            "--no-mdns" => a.mdns = false,
            _ => {
                eprintln!("usage: peerpassd [--data-dir DIR] [--socket PATH] [--port N] [--no-mdns]");
                std::process::exit(2);
            }
        }
    }
    a
}

fn load_identity(dir: &Path) -> std::io::Result<Identity> {
    let p = dir.join("identity.key");
    if let Ok(b) = std::fs::read(&p) {
        let b = Zeroizing::new(b);
        return Identity::from_secret(&b).map_err(|e| std::io::Error::other(e.to_string()));
    }
    let id = Identity::generate();
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?;
    f.write_all(id.secret())?;
    f.sync_all()?;
    Ok(id)
}

fn main() {
    let args = parse_args();
    // Everything we create (DB, key, socket) is private to this user.
    unsafe { libc::umask(0o077) };
    std::fs::create_dir_all(&args.data_dir).expect("create data dir");
    let _ = std::fs::set_permissions(&args.data_dir, std::fs::Permissions::from_mode(0o700));
    let identity = load_identity(&args.data_dir).expect("identity key");
    let db = Storage::open(&args.data_dir.join("peerpass.db")).expect("open db");
    let vault = Arc::new(Mutex::new(Vault::new(db, identity)));

    let shared = Arc::new(Shared::default());
    let sh = shared.clone();
    let approver = Box::new(move |name: &str, code: &str| {
        let mut g = sh.approval.lock().unwrap();
        *g = Some(Approval { name: name.into(), code: code.into(), decision: None });
        sh.rev.fetch_add(1, Ordering::SeqCst);
        let (mut g, _) = sh
            .cv
            .wait_timeout_while(g, APPROVAL_TIMEOUT, |a| a.as_ref().is_some_and(|a| a.decision.is_none()))
            .unwrap();
        g.take().and_then(|a| a.decision).unwrap_or(false)
    });
    let sh = shared.clone();
    let on_change = Box::new(move || {
        sh.rev.fetch_add(1, Ordering::SeqCst);
    });
    let node = Node::new(vault, args.port, approver, on_change);
    node.listen().unwrap_or_else(|e| panic!("cannot listen on TCP port {}: {e}", args.port));
    log(&format!("listening on TCP {}", args.port));

    let _discovery = if args.mdns {
        match Discovery::start(node.clone()) {
            Ok(d) => Some(d),
            Err(e) => {
                log(&format!("mDNS unavailable ({e}); using last known addresses only"));
                None
            }
        }
    } else {
        None
    };

    // Sync worker: on local change or every 5 minutes.
    let (tx, rx) = channel::<()>();
    let n2 = node.clone();
    std::thread::spawn(move || loop {
        match rx.recv_timeout(SYNC_INTERVAL) {
            Ok(()) => while rx.try_recv().is_ok() {},
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        for (p, r) in n2.sync_all() {
            if let Err(e) = r {
                log(&format!("sync with {} failed: {e}", p.name));
            }
        }
    });

    let d = Arc::new(Daemon {
        node,
        shared,
        last_activity: Mutex::new(Instant::now()),
        join: Arc::new(Mutex::new(None)),
        sync_tx: Mutex::new(tx),
    });

    // Auto-lock on idle.
    let d2 = d.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let secs = d2.auto_lock_secs();
        if d2.last_activity.lock().unwrap().elapsed() > Duration::from_secs(secs) {
            let mut v = d2.node.vault.lock().unwrap();
            if v.is_unlocked() {
                v.lock();
                d2.bump();
                log("auto-locked after idle timeout");
            }
        }
    });

    let _ = std::fs::remove_file(&args.socket);
    let listener = UnixListener::bind(&args.socket).expect("bind socket");
    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600)).expect("chmod socket");
    log(&format!("API socket {}", args.socket.display()));
    for s in listener.incoming().flatten() {
        let d = d.clone();
        std::thread::spawn(move || serve(d, s));
    }
}

fn serve(d: Arc<Daemon>, s: UnixStream) {
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut r = BufReader::new(s);
    loop {
        let mut line = Zeroizing::new(String::new());
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let m = req.get("method").and_then(Value::as_str).unwrap_or("");
                let p = req.get("params").cloned().unwrap_or(Value::Null);
                match d.handle(m, &p) {
                    Ok(v) => json!({ "ok": v }),
                    Err(e) => json!({ "error": e }),
                }
            }
            Err(e) => json!({ "error": format!("bad request: {e}") }),
        };
        let mut out = Zeroizing::new(serde_json::to_string(&resp).unwrap());
        out.push('\n');
        if w.write_all(out.as_bytes()).is_err() {
            return;
        }
    }
}

fn s<'a>(p: &'a Value, k: &str) -> Result<&'a str, String> {
    p.get(k).and_then(Value::as_str).ok_or_else(|| format!("missing parameter '{k}'"))
}

fn uuid(p: &Value, k: &str) -> Result<Uuid, String> {
    Uuid::parse_str(s(p, k)?).map_err(|e| e.to_string())
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Display label for a sibling, so conflicting versions can be told apart.
fn label(i: usize, n: usize, e: Option<&Entry>) -> String {
    let what = match e {
        Some(e) => format!("edited {}", fmt_time(e.updated_at)),
        None => "deleted".to_string(),
    };
    if n > 1 {
        format!("version {} of {n} ({what})", i + 1)
    } else {
        what
    }
}

fn fmt_time(ts: i64) -> String {
    // UTC, YYYY-MM-DD HH:MM without pulling in a date crate.
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs / 3600, (secs % 3600) / 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn item_json(it: &EntryItem) -> Value {
    let n = it.siblings.len();
    json!({
        "id": it.id.to_string(),
        "conflict": n > 1,
        "siblings": it.siblings.iter().enumerate().map(|(i, s)| json!({
            "index": i,
            "label": label(i, n, s.entry.as_ref()),
            "deleted": s.entry.is_none(),
            "entry": s.entry,
        })).collect::<Vec<_>>(),
    })
}

impl Daemon {
    fn bump(&self) {
        self.shared.rev.fetch_add(1, Ordering::SeqCst);
    }

    fn changed(&self) {
        self.bump();
        let _ = self.sync_tx.lock().unwrap().send(());
    }

    fn auto_lock_secs(&self) -> u64 {
        let v = self.node.vault.lock().unwrap();
        v.db.get_meta("auto_lock_secs")
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok()?.parse().ok())
            .unwrap_or(DEFAULT_AUTO_LOCK)
    }

    fn handle(&self, method: &str, p: &Value) -> Result<Value, String> {
        // Passive polling (status, TOTP countdown) does not keep the vault unlocked.
        if !matches!(method, "status" | "pair_status" | "totp") {
            *self.last_activity.lock().unwrap() = Instant::now();
        }
        let vault = &self.node.vault;
        match method {
            "status" => {
                let auto_lock = self.auto_lock_secs();
                let v = vault.lock().unwrap();
                let unlocked = v.is_unlocked();
                Ok(json!({
                    "has_vault": v.has_vault().map_err(err)?,
                    "unlocked": unlocked,
                    "device_id": hex::encode(v.device_id()),
                    "device_name": v.db.get_meta("device_name").map_err(err)?.map(|b| String::from_utf8_lossy(&b).into_owned()),
                    "conflicts": if unlocked { v.conflict_count().ok() } else { None },
                    "rev": self.shared.rev.load(Ordering::SeqCst),
                    "auto_lock_secs": auto_lock,
                    "port": self.node.port,
                }))
            }
            "create" => {
                let pw = Zeroizing::new(s(p, "password")?.to_string());
                vault.lock().unwrap().create(&pw, s(p, "device_name")?, KdfParams::default()).map_err(err)?;
                self.changed();
                Ok(Value::Null)
            }
            "unlock" => {
                let pw = Zeroizing::new(s(p, "password")?.to_string());
                vault.lock().unwrap().unlock(&pw).map_err(err)?;
                self.bump();
                Ok(Value::Null)
            }
            "lock" => {
                vault.lock().unwrap().lock();
                self.bump();
                Ok(Value::Null)
            }
            "change_password" => {
                let old = Zeroizing::new(s(p, "old")?.to_string());
                let new = Zeroizing::new(s(p, "new")?.to_string());
                let mut v = vault.lock().unwrap();
                v.unlock(&old).map_err(err)?;
                v.change_password(&new, KdfParams::default()).map_err(err)?;
                drop(v);
                self.changed();
                Ok(Value::Null)
            }
            "list" => {
                let v = vault.lock().unwrap();
                let items = v.list().map_err(err)?;
                Ok(Value::Array(
                    items
                        .iter()
                        .map(|it| {
                            let first = it.siblings.iter().find_map(|s| s.entry.as_ref());
                            json!({
                                "id": it.id.to_string(),
                                "conflict": it.is_conflict(),
                                "title": first.map(|e| e.title.clone()).unwrap_or_default(),
                                "username": first.map(|e| e.username.clone()).unwrap_or_default(),
                                "urls": first.map(|e| e.urls.clone()).unwrap_or_default(),
                            })
                        })
                        .collect(),
                ))
            }
            "get" => Ok(item_json(&vault.lock().unwrap().get(&uuid(p, "id")?).map_err(err)?)),
            "put" => {
                let id = match p.get("id").and_then(Value::as_str) {
                    Some(s) if !s.is_empty() => Some(Uuid::parse_str(s).map_err(err)?),
                    _ => None,
                };
                let e: Entry = serde_json::from_value(p.get("entry").cloned().ok_or("missing entry")?).map_err(err)?;
                let id = vault.lock().unwrap().put(id, e).map_err(err)?;
                self.changed();
                Ok(json!(id.to_string()))
            }
            "delete" => {
                vault.lock().unwrap().delete(&uuid(p, "id")?).map_err(err)?;
                self.changed();
                Ok(Value::Null)
            }
            "generate" => {
                let o: GenOptions = serde_json::from_value(p.clone()).unwrap_or_default();
                Ok(json!(generator::generate(&o).map_err(err)?.as_str()))
            }
            "find" => {
                let url = s(p, "url")?;
                let site = domain::etld1(url).ok_or("not a web page")?;
                let v = vault.lock().unwrap();
                let mut out = Vec::new();
                for it in v.list().map_err(err)? {
                    let n = it.siblings.len();
                    for (i, sib) in it.siblings.iter().enumerate() {
                        let Some(e) = &sib.entry else { continue };
                        if e.urls.iter().any(|u| domain::etld1(u).as_deref() == Some(&site)) {
                            out.push(json!({
                                "id": it.id.to_string(), "index": i, "title": e.title,
                                "username": e.username, "password": e.password,
                                "has_totp": e.totp.is_some(),
                                "label": if n > 1 { label(i, n, Some(e)) } else { String::new() },
                            }));
                        }
                    }
                }
                Ok(Value::Array(out))
            }
            "peers" => {
                let v = vault.lock().unwrap();
                Ok(Value::Array(
                    v.db.peers()
                        .map_err(err)?
                        .into_iter()
                        .map(|p| json!({
                            "device_id": hex::encode(p.device_id), "name": p.name,
                            "last_addr": p.last_addr, "last_sync": p.last_sync,
                        }))
                        .collect(),
                ))
            }
            "remove_peer" => {
                let d: [u8; 8] = hex::decode(s(p, "device_id")?).ok().and_then(|b| b.try_into().ok()).ok_or("bad device id")?;
                vault.lock().unwrap().remove_device(&d).map_err(err)?;
                self.changed();
                Ok(Value::Null)
            }
            "sync_now" => {
                let res = self.node.sync_all();
                Ok(Value::Array(
                    res.into_iter()
                        .map(|(p, r)| json!({ "name": p.name, "ok": r.is_ok(), "error": r.err().map(|e| e.to_string()) }))
                        .collect(),
                ))
            }
            "pair_begin" => {
                let o = self.node.begin_pairing().map_err(err)?;
                Ok(json!({ "text": o.to_text(), "expires": o.expires }))
            }
            "pair_cancel" => {
                self.node.cancel_pairing();
                Ok(Value::Null)
            }
            "pair_status" => {
                let a = self.shared.approval.lock().unwrap();
                let pending = a.as_ref().filter(|a| a.decision.is_none()).map(|a| json!({ "name": a.name, "code": a.code }));
                let j = self.join.lock().unwrap().clone();
                Ok(json!({
                    "pending": pending,
                    "join": j.map(|j| json!({ "code": j.code, "done": j.done, "error": j.error, "peer": j.peer })),
                }))
            }
            "pair_respond" => {
                let accept = p.get("accept").and_then(Value::as_bool).ok_or("missing accept")?;
                if let Some(a) = self.shared.approval.lock().unwrap().as_mut() {
                    a.decision = Some(accept);
                }
                self.shared.cv.notify_all();
                Ok(Value::Null)
            }
            "pair_join" => {
                let text = s(p, "text")?.to_string();
                let name = s(p, "device_name")?.to_string();
                *self.join.lock().unwrap() = Some(JoinState::default());
                let (node, join, shared) = (self.node.clone(), self.join.clone(), self.shared.clone());
                std::thread::spawn(move || {
                    let j2 = join.clone();
                    let r = node.join(&text, &name, &move |c| {
                        if let Some(j) = j2.lock().unwrap().as_mut() {
                            j.code = Some(c.to_string());
                        }
                    });
                    if let Some(j) = join.lock().unwrap().as_mut() {
                        j.done = true;
                        match r {
                            Ok(n) => j.peer = Some(n),
                            Err(e) => j.error = Some(e.to_string()),
                        }
                    }
                    shared.rev.fetch_add(1, Ordering::SeqCst);
                });
                Ok(Value::Null)
            }
            "totp" => {
                let v = vault.lock().unwrap();
                let it = v.get(&uuid(p, "id")?).map_err(err)?;
                let i = p.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let e = it.siblings.get(i).and_then(|s| s.entry.as_ref()).ok_or("no such version")?;
                let t = Totp::parse(e.totp.as_deref().ok_or("entry has no TOTP")?).map_err(err)?;
                let (code, remaining) = t.now();
                Ok(json!({ "code": code, "remaining": remaining, "period": t.period }))
            }
            "import" => {
                let path = s(p, "path")?;
                let data = Zeroizing::new(std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?);
                let entries = match s(p, "format")? {
                    "kdbx" => import::parse_kdbx(&data, p.get("password").and_then(Value::as_str).unwrap_or("")),
                    "bitwarden" => import::parse_bitwarden(&data),
                    f => return Err(format!("unknown format '{f}'")),
                }
                .map_err(err)?;
                let sum = import::import_entries(&mut vault.lock().unwrap(), entries).map_err(err)?;
                self.changed();
                Ok(json!({ "imported": sum.imported, "skipped": sum.skipped }))
            }
            "set_auto_lock" => {
                let secs = p.get("secs").and_then(Value::as_u64).filter(|s| *s >= 30).ok_or("secs >= 30 required")?;
                vault.lock().unwrap().db.set_meta("auto_lock_secs", secs.to_string().as_bytes()).map_err(err)?;
                Ok(Value::Null)
            }
            _ => Err(format!("unknown method '{method}'")),
        }
    }
}
