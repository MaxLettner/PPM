//! High-level vault operations: create/unlock, CRUD with version vectors, trust list.
use crate::crypto::{self, KdfParams, Key};
use crate::identity::Identity;
use crate::model::*;
use crate::storage::Storage;
use crate::{Error, Result};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Vault {
    pub db: Storage,
    identity: Identity,
    key: Option<Key>,
}

/// One version of an entry. `entry` is None for a tombstone.
#[derive(Clone, Debug)]
pub struct Sibling {
    pub vv: VersionVector,
    pub entry: Option<Entry>,
}

#[derive(Clone, Debug)]
pub struct EntryItem {
    pub id: Uuid,
    pub siblings: Vec<Sibling>,
}

impl EntryItem {
    pub fn is_conflict(&self) -> bool {
        self.siblings.len() > 1
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn aad(vault_id: &Uuid, id: &Uuid) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..16].copy_from_slice(vault_id.as_bytes());
    a[16..].copy_from_slice(id.as_bytes());
    a
}

fn wrap_aad(vault_id: &Uuid) -> Vec<u8> {
    [b"peerpass-header".as_slice(), vault_id.as_bytes()].concat()
}

impl Vault {
    pub fn new(db: Storage, identity: Identity) -> Self {
        Self { db, identity, key: None }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    pub fn has_vault(&self) -> Result<bool> {
        Ok(self.db.header()?.is_some())
    }

    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    fn header(&self) -> Result<VaultHeader> {
        self.db.header()?.ok_or(Error::NoVault)
    }

    fn key(&self) -> Result<&Key> {
        self.key.as_ref().ok_or(Error::Locked)
    }

    pub fn vault_id(&self) -> Result<Uuid> {
        Ok(self.header()?.vault_id)
    }

    /// Creates a new vault on this (first) device.
    pub fn create(&mut self, password: &str, device_name: &str, kdf: KdfParams) -> Result<()> {
        if self.has_vault()? {
            return Err(Error::VaultExists);
        }
        if password.is_empty() {
            return Err(Error::Invalid("empty master password".into()));
        }
        let vault_id = Uuid::now_v7();
        let kv = crypto::random_key();
        let salt = crypto::random_bytes::<16>();
        let kek = crypto::derive_key(password.as_bytes(), &salt, &kdf)?;
        let mut vv = VersionVector::default();
        vv.increment(self.device_id());
        let header = VaultHeader { vault_id, kdf, salt, wrapped_key: crypto::seal(&kek, &wrap_aad(&vault_id), &*kv), vv };
        self.db.set_header(&header)?;
        self.key = Some(kv);
        let info = DeviceInfo { pubkey: *self.identity.public(), name: device_name.to_string() };
        self.add_device(info)?;
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let h = self.header()?;
        let kek = crypto::derive_key(password.as_bytes(), &h.salt, &h.kdf)?;
        let raw = crypto::open(&kek, &wrap_aad(&h.vault_id), &h.wrapped_key).map_err(|_| Error::WrongPassword)?;
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&raw);
        self.key = Some(k);
        self.on_unlock()
    }

    /// Unlock with a raw K_v (Android biometric path). Verified against our own device record.
    pub fn unlock_with_key(&mut self, key: &[u8]) -> Result<()> {
        let k: [u8; 32] = key.try_into().map_err(|_| Error::Invalid("key length".into()))?;
        let vault_id = self.vault_id()?;
        let rid = device_record_id(&self.device_id());
        let own = self.db.siblings(&rid)?;
        let ok = own.iter().any(|r| !r.deleted && crypto::open(&k, &aad(&vault_id, &rid), &r.blob).is_ok());
        if !ok {
            return Err(Error::WrongPassword);
        }
        self.key = Some(Zeroizing::new(k));
        self.on_unlock()
    }

    /// Raw K_v for wrapping by a platform keystore (Android biometric).
    pub fn export_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.key()?.to_vec()))
    }

    pub fn header_fingerprint(&self) -> Result<String> {
        Ok(self.header()?.fingerprint())
    }

    fn on_unlock(&mut self) -> Result<()> {
        // Make sure our own trust-list record exists (e.g. a freshly paired device).
        let me = device_record_id(&self.device_id());
        if self.db.siblings(&me)?.is_empty() {
            let name = self.db.get_meta("device_name")?.map(|b| String::from_utf8_lossy(&b).into_owned());
            let info = DeviceInfo { pubkey: *self.identity.public(), name: name.unwrap_or_else(|| "device".into()) };
            self.write_record(me, RecordKind::Device, Some(&postcard::to_allocvec(&info)?))?;
        }
        self.refresh_peers()
    }

    pub fn lock(&mut self) {
        self.key = None;
    }

    pub fn change_password(&mut self, new_password: &str, kdf: KdfParams) -> Result<()> {
        if new_password.is_empty() {
            return Err(Error::Invalid("empty master password".into()));
        }
        let kv = self.key()?.clone();
        let mut h = self.header()?;
        h.salt = crypto::random_bytes::<16>();
        h.kdf = kdf;
        let kek = crypto::derive_key(new_password.as_bytes(), &h.salt, &h.kdf)?;
        h.wrapped_key = crypto::seal(&kek, &wrap_aad(&h.vault_id), &*kv);
        h.vv.increment(self.device_id());
        self.db.set_header(&h)
    }

    /// Applies a header received from a peer. Returns true if it replaced ours.
    pub fn apply_header(&mut self, incoming: VaultHeader) -> Result<bool> {
        match self.db.header()? {
            None => {
                self.db.set_header(&incoming)?;
                Ok(true)
            }
            Some(h) if h.vault_id != incoming.vault_id => Err(Error::Protocol("vault id mismatch".into())),
            Some(h) if h.should_replace_with(&incoming) => {
                self.db.set_header(&incoming)?;
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    // ---- records ----

    fn decrypt_entry(&self, vault_id: &Uuid, r: &Record) -> Result<Sibling> {
        let entry = if r.deleted {
            None
        } else {
            let pt = crypto::open(self.key()?, &aad(vault_id, &r.id), &r.blob)?;
            Some(postcard::from_bytes(&pt)?)
        };
        Ok(Sibling { vv: r.vv.clone(), entry })
    }

    fn item(&self, vault_id: &Uuid, id: Uuid, recs: &[Record]) -> Result<EntryItem> {
        let siblings = recs.iter().map(|r| self.decrypt_entry(vault_id, r)).collect::<Result<_>>()?;
        Ok(EntryItem { id, siblings })
    }

    /// All visible entries (tombstone-only items are hidden). Requires unlock.
    pub fn list(&self) -> Result<Vec<EntryItem>> {
        let vault_id = self.vault_id()?;
        self.key()?;
        let recs = self.db.records_of_kind(RecordKind::Entry)?;
        let mut out = Vec::new();
        for chunk in recs.chunk_by(|a, b| a.id == b.id) {
            if chunk.iter().all(|r| r.deleted) {
                continue;
            }
            out.push(self.item(&vault_id, chunk[0].id, chunk)?);
        }
        Ok(out)
    }

    pub fn get(&self, id: &Uuid) -> Result<EntryItem> {
        let recs = self.db.siblings(id)?;
        if recs.is_empty() || recs[0].kind != RecordKind::Entry {
            return Err(Error::NotFound);
        }
        self.item(&self.vault_id()?, *id, &recs)
    }

    pub fn conflict_count(&self) -> Result<usize> {
        Ok(self.list()?.iter().filter(|i| i.is_conflict()).count())
    }

    /// Local edit: vv = merge(all siblings) + 1 for this device; replaces all siblings.
    fn write_record(&mut self, id: Uuid, kind: RecordKind, plaintext: Option<&[u8]>) -> Result<()> {
        let vault_id = self.vault_id()?;
        let key = self.key()?;
        let mut vv = VersionVector::default();
        for s in self.db.siblings(&id)? {
            vv.merge(&s.vv);
        }
        vv.increment(self.device_id());
        let (deleted, blob) = match plaintext {
            Some(p) => (false, crypto::seal(key, &aad(&vault_id, &id), p)),
            None => (true, Vec::new()),
        };
        self.db.replace_siblings(&id, &[Record { id, kind, vv, deleted, blob }])
    }

    /// Creates (id = None) or edits an entry. Editing also resolves any conflict.
    pub fn put(&mut self, id: Option<Uuid>, mut entry: Entry) -> Result<Uuid> {
        let id = id.unwrap_or_else(Uuid::now_v7);
        if let Some(r) = self.db.siblings(&id)?.first()
            && r.kind != RecordKind::Entry {
                return Err(Error::Invalid("not an entry".into()));
            }
        entry.updated_at = now();
        let pt = Zeroizing::new(postcard::to_allocvec(&entry)?);
        self.write_record(id, RecordKind::Entry, Some(&pt))?;
        Ok(id)
    }

    pub fn delete(&mut self, id: &Uuid) -> Result<()> {
        self.key()?;
        if self.db.siblings(id)?.is_empty() {
            return Err(Error::NotFound);
        }
        self.write_record(*id, RecordKind::Entry, None)
    }

    // ---- trust list ----

    /// Trusted devices (non-deleted device records). Requires unlock.
    pub fn devices(&self) -> Result<Vec<(DeviceId, DeviceInfo)>> {
        let vault_id = self.vault_id()?;
        let key = self.key()?;
        let recs = self.db.records_of_kind(RecordKind::Device)?;
        let mut out = Vec::new();
        for chunk in recs.chunk_by(|a, b| a.id == b.id) {
            // Removal wins over a concurrent edit: any tombstone sibling = untrusted.
            if chunk.iter().any(|r| r.deleted) {
                continue;
            }
            let pt = crypto::open(key, &aad(&vault_id, &chunk[0].id), &chunk[0].blob)?;
            let info: DeviceInfo = postcard::from_bytes(&pt)?;
            let d = device_id_from_pubkey(&info.pubkey);
            if device_record_id(&d) == chunk[0].id {
                out.push((d, info));
            }
        }
        Ok(out)
    }

    /// Adds a device to the trust list and to local peers. Requires unlock.
    pub fn add_device(&mut self, info: DeviceInfo) -> Result<()> {
        let d = device_id_from_pubkey(&info.pubkey);
        if d == self.device_id() {
            self.db.set_meta("device_name", info.name.as_bytes())?;
        } else {
            self.db.upsert_peer(&d, &info.pubkey, &info.name)?;
        }
        self.write_record(device_record_id(&d), RecordKind::Device, Some(&postcard::to_allocvec(&info)?))
    }

    /// Removes a device from the trust list (tombstone) and local peers. Requires unlock.
    pub fn remove_device(&mut self, d: &DeviceId) -> Result<()> {
        self.key()?;
        self.write_record(device_record_id(d), RecordKind::Device, None)?;
        self.db.remove_peer(d)
    }

    /// Syncs local `peers` with the decrypted trust list.
    pub fn refresh_peers(&mut self) -> Result<()> {
        let trusted = self.devices()?;
        let me = self.device_id();
        for (d, info) in &trusted {
            if *d != me {
                self.db.upsert_peer(d, &info.pubkey, &info.name)?;
            }
        }
        for p in self.db.peers()? {
            let rid = device_record_id(&p.device_id);
            let recs = self.db.siblings(&rid)?;
            // Only drop peers the trust list explicitly removed; a peer we just paired
            // with but whose record has not synced yet stays.
            if recs.iter().any(|r| r.deleted) {
                self.db.remove_peer(&p.device_id)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fast_kdf() -> KdfParams {
        KdfParams { m_kib: 64, t: 1, p: 1 }
    }

    pub fn new_vault() -> Vault {
        let mut v = Vault::new(Storage::open_in_memory().unwrap(), Identity::generate());
        v.create("pw", "dev", fast_kdf()).unwrap();
        v
    }

    fn entry(t: &str) -> Entry {
        let mut e = Entry::default();
        e.title = t.into();
        e.username = "u".into();
        e.password = "p".into();
        e
    }

    #[test]
    fn create_unlock_crud() {
        let mut v = new_vault();
        let id = v.put(None, entry("a")).unwrap();
        assert_eq!(v.list().unwrap().len(), 1);
        v.lock();
        assert!(matches!(v.list(), Err(Error::Locked)));
        assert!(matches!(v.unlock("nope"), Err(Error::WrongPassword)));
        v.unlock("pw").unwrap();
        let it = v.get(&id).unwrap();
        assert_eq!(it.siblings[0].entry.as_ref().unwrap().title, "a");
        v.put(Some(id), entry("b")).unwrap();
        assert_eq!(v.get(&id).unwrap().siblings.len(), 1);
        assert_eq!(v.get(&id).unwrap().siblings[0].vv.get(&v.device_id()), 2);
        v.delete(&id).unwrap();
        assert!(v.list().unwrap().is_empty());
    }

    #[test]
    fn blobs_are_encrypted_and_bound_to_id() {
        let mut v = new_vault();
        let id = v.put(None, entry("SuperSecretTitle")).unwrap();
        let rec = &v.db.siblings(&id).unwrap()[0];
        assert!(!rec.blob.windows(16).any(|w| w == b"SuperSecretTitle"));
        // Moving a blob to another id must fail authentication.
        let other = Uuid::now_v7();
        let mut moved = rec.clone();
        moved.id = other;
        v.db.apply_incoming(moved).unwrap();
        assert!(v.get(&other).is_err());
    }

    #[test]
    fn change_password_and_key_unlock() {
        let mut v = new_vault();
        let fp = v.header_fingerprint().unwrap();
        let k = v.export_key().unwrap();
        v.change_password("new", fast_kdf()).unwrap();
        assert_ne!(fp, v.header_fingerprint().unwrap());
        v.lock();
        assert!(v.unlock("pw").is_err());
        v.unlock("new").unwrap();
        v.lock();
        v.unlock_with_key(&k).unwrap();
        v.lock();
        assert!(v.unlock_with_key(&[0u8; 32]).is_err());
    }

    #[test]
    fn trust_list() {
        let mut v = new_vault();
        let other = Identity::generate();
        v.add_device(DeviceInfo { pubkey: *other.public(), name: "phone".into() }).unwrap();
        assert_eq!(v.db.peers().unwrap().len(), 1);
        assert_eq!(v.devices().unwrap().len(), 2);
        v.remove_device(&other.device_id()).unwrap();
        assert!(v.db.peers().unwrap().is_empty());
        assert_eq!(v.devices().unwrap().len(), 1);
    }
}
