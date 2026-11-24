//! UniFFI surface of peerpass-core for the Android app (Kotlin).
//! Kotlin owns platform concerns: Keystore-wrapped identity, biometrics, MulticastLock,
//! WorkManager scheduling, auto-lock timers and the clipboard.
use peerpass_core::crypto::KdfParams;
use peerpass_core::generator::{self, GenOptions};
use peerpass_core::identity::Identity;
use peerpass_core::model::{CustomField, Entry};
use peerpass_core::storage::Storage;
use peerpass_core::sync::approval::PairingUi;
use peerpass_core::sync::discovery::Discovery;
use peerpass_core::sync::node::Node;
use peerpass_core::totp::Totp;
use peerpass_core::vault::{EntryItem, Vault};
use peerpass_core::{domain, import};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PpError {
    #[error("vault is locked")]
    Locked,
    #[error("wrong master password")]
    WrongPassword,
    #[error("{msg}")]
    Failed { msg: String },
}

impl From<peerpass_core::Error> for PpError {
    fn from(e: peerpass_core::Error) -> Self {
        match e {
            peerpass_core::Error::Locked => PpError::Locked,
            peerpass_core::Error::WrongPassword => PpError::WrongPassword,
            e => PpError::Failed { msg: e.to_string() },
        }
    }
}

fn fail(msg: impl ToString) -> PpError {
    PpError::Failed { msg: msg.to_string() }
}

type R<T> = Result<T, PpError>;

#[derive(uniffi::Record, Clone)]
pub struct Field {
    pub name: String,
    pub value: String,
}

#[derive(uniffi::Record, Clone)]
pub struct EntryData {
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub totp: Option<String>,
    pub custom_fields: Vec<Field>,
    pub updated_at: i64,
}

impl From<&Entry> for EntryData {
    fn from(e: &Entry) -> Self {
        Self {
            title: e.title.clone(),
            username: e.username.clone(),
            password: e.password.clone(),
            urls: e.urls.clone(),
            notes: e.notes.clone(),
            totp: e.totp.clone(),
            custom_fields: e.custom_fields.iter().map(|f| Field { name: f.name.clone(), value: f.value.clone() }).collect(),
            updated_at: e.updated_at,
        }
    }
}

impl From<EntryData> for Entry {
    fn from(d: EntryData) -> Self {
        let mut e = Entry::default();
        e.title = d.title;
        e.username = d.username;
        e.password = d.password;
        e.urls = d.urls;
        e.notes = d.notes;
        e.totp = d.totp.filter(|t| !t.trim().is_empty());
        e.custom_fields = d.custom_fields.into_iter().map(|f| CustomField { name: f.name, value: f.value }).collect();
        e
    }
}

#[derive(uniffi::Record)]
pub struct Version {
    pub index: u32,
    pub label: String,
    /// None = deleted on some device.
    pub entry: Option<EntryData>,
}

#[derive(uniffi::Record)]
pub struct Item {
    pub id: String,
    pub versions: Vec<Version>,
}

#[derive(uniffi::Record)]
pub struct Summary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub conflict: bool,
}

#[derive(uniffi::Record)]
pub struct Credential {
    pub id: String,
    pub index: u32,
    pub title: String,
    pub username: String,
    pub password: String,
    /// Non-empty when the entry has conflicting versions.
    pub label: String,
}

#[derive(uniffi::Record)]
pub struct PeerInfo {
    pub device_id: String,
    pub name: String,
    pub last_addr: Option<String>,
    pub last_sync: Option<i64>,
}

#[derive(uniffi::Record)]
pub struct SyncResult {
    pub name: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

#[derive(uniffi::Record)]
pub struct PairStatus {
    pub pending_name: Option<String>,
    pub pending_code: Option<String>,
    pub joining: bool,
    pub join_code: Option<String>,
    pub join_done: bool,
    pub join_error: Option<String>,
    pub join_peer: Option<String>,
}

#[derive(uniffi::Record)]
pub struct ImportResult {
    pub imported: u32,
    pub skipped: u32,
}

#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    /// Vault content, peers or pairing state changed (called from a background thread).
    fn on_change(&self);
}

/// New random device identity secret (to be wrapped by Android Keystore).
#[uniffi::export]
pub fn generate_identity() -> Vec<u8> {
    Identity::generate().secret().to_vec()
}

#[uniffi::export]
pub fn generate_password(length: u32, lower: bool, upper: bool, digits: bool, symbols: bool) -> R<String> {
    Ok(generator::generate(&GenOptions { length, lower, upper, digits, symbols })?.to_string())
}

/// Registrable domain (eTLD+1) for autofill matching.
#[uniffi::export]
pub fn etld1(host_or_url: String) -> Option<String> {
    domain::etld1(&host_or_url)
}

/// Milliseconds one master-password derivation takes on this device (default params).
#[uniffi::export]
pub fn kdf_benchmark_millis() -> u64 {
    let t = Instant::now();
    let _ = peerpass_core::crypto::derive_key(b"benchmark", &[0u8; 16], &KdfParams::default());
    t.elapsed().as_millis() as u64
}

#[derive(uniffi::Object)]
pub struct PeerPass {
    node: Arc<Node>,
    pairing: Arc<PairingUi>,
    listener: Arc<Mutex<Option<Box<dyn EventListener>>>>,
    discovery: Mutex<Option<Discovery>>,
    listening: OnceLock<()>,
}

fn label(i: usize, n: usize, e: Option<&Entry>) -> String {
    let what = match e {
        Some(_) => "edited",
        None => "deleted",
    };
    if n > 1 {
        format!("version {} of {n} ({what})", i + 1)
    } else {
        String::new()
    }
}

fn item(it: &EntryItem) -> Item {
    let n = it.siblings.len();
    Item {
        id: it.id.to_string(),
        versions: it
            .siblings
            .iter()
            .enumerate()
            .map(|(i, s)| Version { index: i as u32, label: label(i, n, s.entry.as_ref()), entry: s.entry.as_ref().map(EntryData::from) })
            .collect(),
    }
}

fn parse_id(id: &str) -> R<Uuid> {
    Uuid::parse_str(id).map_err(fail)
}

#[uniffi::export]
impl PeerPass {
    /// Opens (or creates) the DB at `db_path` with this device's identity secret.
    #[uniffi::constructor]
    pub fn new(db_path: String, identity_secret: Vec<u8>, port: u16) -> R<Arc<Self>> {
        let secret = Zeroizing::new(identity_secret);
        let identity = Identity::from_secret(&secret)?;
        let db = Storage::open(std::path::Path::new(&db_path))?;
        let vault = Arc::new(Mutex::new(Vault::new(db, identity)));
        let listener: Arc<Mutex<Option<Box<dyn EventListener>>>> = Arc::new(Mutex::new(None));
        let pairing = Arc::new(PairingUi::default());
        let (l1, l2) = (listener.clone(), listener.clone());
        let approver = pairing.approver(move || notify(&l1));
        let node = Node::new(vault, port, approver, Box::new(move || notify(&l2)));
        Ok(Arc::new(Self { node, pairing, listener, discovery: Mutex::new(None), listening: OnceLock::new() }))
    }

    pub fn set_listener(&self, l: Box<dyn EventListener>) {
        *self.listener.lock().unwrap() = Some(l);
    }

    pub fn has_vault(&self) -> R<bool> {
        Ok(self.v().has_vault()?)
    }

    pub fn is_unlocked(&self) -> bool {
        self.v().is_unlocked()
    }

    pub fn device_id(&self) -> String {
        hex::encode(self.v().device_id())
    }

    pub fn device_name(&self) -> Option<String> {
        self.v().db.get_meta("device_name").ok().flatten().map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub fn create_vault(&self, password: String, device_name: String) -> R<()> {
        let pw = Zeroizing::new(password);
        self.v().create(&pw, &device_name, KdfParams::default())?;
        self.changed();
        Ok(())
    }

    pub fn unlock(&self, password: String) -> R<()> {
        let pw = Zeroizing::new(password);
        self.v().unlock(&pw)?;
        Ok(())
    }

    /// Biometric path: K_v unwrapped by the Keystore.
    pub fn unlock_with_key(&self, key: Vec<u8>) -> R<()> {
        let k = Zeroizing::new(key);
        self.v().unlock_with_key(&k)?;
        Ok(())
    }

    /// K_v, for wrapping with a biometric-bound Keystore key. Requires unlock.
    pub fn export_key(&self) -> R<Vec<u8>> {
        Ok(self.v().export_key()?.to_vec())
    }

    /// Changes whenever the synced header (master password) changes.
    pub fn header_fingerprint(&self) -> R<String> {
        Ok(self.v().header_fingerprint()?)
    }

    pub fn lock(&self) {
        self.v().lock();
    }

    pub fn change_password(&self, old: String, new: String) -> R<()> {
        let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
        let mut v = self.v();
        v.unlock(&old)?;
        v.change_password(&new, KdfParams::default())?;
        drop(v);
        self.changed();
        Ok(())
    }

    pub fn list(&self) -> R<Vec<Summary>> {
        Ok(self
            .v()
            .list()?
            .iter()
            .map(|it| {
                let e = it.siblings.iter().find_map(|s| s.entry.as_ref());
                Summary {
                    id: it.id.to_string(),
                    title: e.map(|e| e.title.clone()).unwrap_or_default(),
                    username: e.map(|e| e.username.clone()).unwrap_or_default(),
                    urls: e.map(|e| e.urls.clone()).unwrap_or_default(),
                    conflict: it.is_conflict(),
                }
            })
            .collect())
    }

    pub fn get(&self, id: String) -> R<Item> {
        Ok(item(&self.v().get(&parse_id(&id)?)?))
    }

    pub fn conflict_count(&self) -> R<u32> {
        Ok(self.v().conflict_count()? as u32)
    }

    /// Creates (id = None) or replaces an entry; replacing also resolves conflicts.
    pub fn put(&self, id: Option<String>, entry: EntryData) -> R<String> {
        let id = id.filter(|s| !s.is_empty()).map(|s| parse_id(&s)).transpose()?;
        let id = self.v().put(id, entry.into())?;
        self.changed();
        Ok(id.to_string())
    }

    pub fn delete(&self, id: String) -> R<()> {
        self.v().delete(&parse_id(&id)?)?;
        self.changed();
        Ok(())
    }

    pub fn totp(&self, id: String, index: u32) -> R<TotpCode> {
        let it = self.v().get(&parse_id(&id)?)?;
        let e = it.siblings.get(index as usize).and_then(|s| s.entry.as_ref()).ok_or_else(|| fail("no such version"))?;
        let t = Totp::parse(e.totp.as_deref().ok_or_else(|| fail("entry has no TOTP"))?)?;
        let (code, remaining) = t.now();
        Ok(TotpCode { code, remaining, period: t.period })
    }

    /// Autofill candidates: by web domain (eTLD+1) and/or Android package name
    /// (matched against `androidapp://<package>` URLs). Every conflicting version is listed.
    pub fn find_for_autofill(&self, web_domain: Option<String>, package_name: Option<String>) -> R<Vec<Credential>> {
        let site = web_domain.as_deref().and_then(domain::etld1);
        let app = package_name.map(|p| format!("androidapp://{p}"));
        let mut out = Vec::new();
        for it in self.v().list()? {
            let n = it.siblings.len();
            for (i, s) in it.siblings.iter().enumerate() {
                let Some(e) = &s.entry else { continue };
                let hit = e.urls.iter().any(|u| {
                    let u2 = u.trim().to_ascii_lowercase();
                    app.as_deref().is_some_and(|a| u2 == a) || site.is_some() && !u2.starts_with("androidapp://") && domain::etld1(u) == site
                });
                if hit {
                    out.push(Credential {
                        id: it.id.to_string(),
                        index: i as u32,
                        title: e.title.clone(),
                        username: e.username.clone(),
                        password: e.password.clone(),
                        label: label(i, n, Some(e)),
                    });
                }
            }
        }
        Ok(out)
    }

    pub fn peers(&self) -> R<Vec<PeerInfo>> {
        Ok(self
            .v()
            .db
            .peers()?
            .into_iter()
            .map(|p| PeerInfo { device_id: hex::encode(p.device_id), name: p.name, last_addr: p.last_addr, last_sync: p.last_sync })
            .collect())
    }

    pub fn remove_peer(&self, device_id: String) -> R<()> {
        let d: [u8; 8] = hex::decode(&device_id).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| fail("bad device id"))?;
        self.v().remove_device(&d)?;
        self.changed();
        Ok(())
    }

    /// App in foreground: accept connections and run mDNS (hold a MulticastLock in Kotlin).
    pub fn start_network(&self) -> R<()> {
        if self.listening.get().is_none() {
            self.node.listen()?;
            let _ = self.listening.set(());
        }
        let mut d = self.discovery.lock().unwrap();
        if d.is_none() {
            *d = Some(Discovery::start(self.node.clone())?);
        }
        Ok(())
    }

    pub fn stop_network(&self) {
        if let Some(d) = self.discovery.lock().unwrap().take() {
            d.stop();
        }
    }

    pub fn sync_all(&self) -> Vec<SyncResult> {
        self.node
            .sync_all()
            .into_iter()
            .map(|(p, r)| SyncResult { name: p.name, ok: r.is_ok(), error: r.err().map(|e| e.to_string()) })
            .collect()
    }

    /// Background job: sync with last known addresses, keep discovering for `seconds`
    /// (discovered peers sync automatically), then stop. Returns the direct-sync results.
    pub fn background_sync(&self, seconds: u32) -> Vec<SyncResult> {
        let started_here = self.discovery.lock().unwrap().is_none();
        let _ = self.start_network();
        let res = self.sync_all();
        let end = Instant::now() + Duration::from_secs(seconds as u64);
        while Instant::now() < end {
            std::thread::sleep(Duration::from_millis(500));
        }
        if started_here {
            self.stop_network();
        }
        res
    }

    /// Existing device: returns the pairing payload (QR content / copyable text).
    pub fn pair_begin(&self) -> R<String> {
        Ok(self.node.begin_pairing()?.to_text())
    }

    pub fn pair_cancel(&self) {
        self.node.cancel_pairing();
    }

    pub fn pair_respond(&self, accept: bool) {
        self.pairing.respond(accept);
    }

    /// New device: join with a scanned/pasted payload. Progress via `pair_status`.
    pub fn pair_join(&self, text: String, device_name: String) {
        let l = self.listener.clone();
        self.pairing.start_join(self.node.clone(), text, device_name, move || notify(&l));
    }

    pub fn pair_status(&self) -> PairStatus {
        let p = self.pairing.pending();
        let j = self.pairing.join_state();
        PairStatus {
            pending_name: p.as_ref().map(|x| x.0.clone()),
            pending_code: p.map(|x| x.1),
            joining: j.is_some(),
            join_code: j.as_ref().and_then(|j| j.code.clone()),
            join_done: j.as_ref().is_some_and(|j| j.done),
            join_error: j.as_ref().and_then(|j| j.error.clone()),
            join_peer: j.and_then(|j| j.peer),
        }
    }

    /// `format`: "kdbx" or "bitwarden". `data` is the file content read via SAF.
    pub fn import_data(&self, format: String, data: Vec<u8>, password: String) -> R<ImportResult> {
        let (data, pw) = (Zeroizing::new(data), Zeroizing::new(password));
        let entries = match format.as_str() {
            "kdbx" => import::parse_kdbx(&data, &pw)?,
            "bitwarden" => import::parse_bitwarden(&data)?,
            _ => return Err(fail("unknown format")),
        };
        let s = import::import_entries(&mut self.v(), entries)?;
        self.changed();
        Ok(ImportResult { imported: s.imported as u32, skipped: s.skipped as u32 })
    }
}

fn notify(l: &Mutex<Option<Box<dyn EventListener>>>) {
    if let Some(l) = l.lock().unwrap().as_ref() {
        l.on_change();
    }
}

impl PeerPass {
    fn v(&self) -> MutexGuard<'_, Vault> {
        self.node.vault.lock().unwrap()
    }

    fn changed(&self) {
        notify(&self.listener);
    }
}
