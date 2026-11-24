//! Data model: version vectors, records (opaque encrypted blobs), plaintext entries.
use crate::crypto::KdfParams;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 8 bytes of BLAKE2s(device static public key).
pub type DeviceId = [u8; 8];

pub fn device_id_from_pubkey(pubkey: &[u8; 32]) -> DeviceId {
    let h = crate::crypto::blake2s(pubkey);
    h[..8].try_into().unwrap()
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionVector(pub BTreeMap<DeviceId, u64>);

impl VersionVector {
    pub fn get(&self, d: &DeviceId) -> u64 {
        self.0.get(d).copied().unwrap_or(0)
    }

    pub fn increment(&mut self, d: DeviceId) {
        *self.0.entry(d).or_insert(0) += 1;
    }

    /// Pointwise max.
    pub fn merge(&mut self, other: &VersionVector) {
        for (d, c) in &other.0 {
            let e = self.0.entry(*d).or_insert(0);
            *e = (*e).max(*c);
        }
    }

    /// Partial order; `None` means concurrent.
    pub fn compare(&self, other: &VersionVector) -> Option<Ordering> {
        let (mut ge, mut le) = (true, true);
        for d in self.0.keys().chain(other.0.keys()) {
            let (a, b) = (self.get(d), other.get(d));
            ge &= a >= b;
            le &= a <= b;
        }
        match (ge, le) {
            (true, true) => Some(Ordering::Equal),
            (true, false) => Some(Ordering::Greater),
            (false, true) => Some(Ordering::Less),
            (false, false) => None,
        }
    }

    /// self >= other
    pub fn ge(&self, other: &VersionVector) -> bool {
        matches!(self.compare(other), Some(Ordering::Greater | Ordering::Equal))
    }

    /// self > other (strictly dominates)
    pub fn dominates(&self, other: &VersionVector) -> bool {
        self.compare(other) == Some(Ordering::Greater)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RecordKind {
    Entry = 0,
    /// Trust-list record: an encrypted `DeviceInfo`.
    Device = 1,
}

impl RecordKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Entry),
            1 => Some(Self::Device),
            _ => None,
        }
    }
}

/// A stored/synced record. `blob` is K_v-encrypted (empty for tombstones).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub kind: RecordKind,
    pub vv: VersionVector,
    pub deleted: bool,
    pub blob: Vec<u8>,
}

/// Merge rule for an incoming sibling `s` against local siblings.
/// Returns true if `local` changed.
pub fn merge_sibling(local: &mut Vec<Record>, s: Record) -> bool {
    if local.iter().any(|l| l.vv.ge(&s.vv)) {
        return false;
    }
    local.retain(|l| !s.vv.dominates(&l.vv));
    local.push(s);
    true
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub name: String,
    pub value: String,
}

/// Plaintext entry. Only ever exists in memory while unlocked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub totp: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub updated_at: i64,
}

/// Plaintext of a trust-list record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub pubkey: [u8; 32],
    pub name: String,
}

/// Synced vault header: KDF params + salt + K_v wrapped by the password-derived key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    pub vault_id: Uuid,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub wrapped_key: Vec<u8>,
    pub vv: VersionVector,
}

impl VaultHeader {
    /// Should `incoming` replace `self`? Newer wins; concurrent changes (two devices
    /// changing the master password at the same time) are resolved deterministically
    /// by comparing the encoded headers, so all devices converge on the same one.
    pub fn should_replace_with(&self, incoming: &VaultHeader) -> bool {
        match incoming.vv.compare(&self.vv) {
            Some(Ordering::Greater) => true,
            None => postcard::to_allocvec(incoming).unwrap() > postcard::to_allocvec(self).unwrap(),
            _ => false,
        }
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(&crate::crypto::blake2s(&postcard::to_allocvec(self).unwrap())[..16])
    }
}

/// Device id of a trust-list record: deterministic so updates/removals hit one id.
pub fn device_record_id(d: &DeviceId) -> Uuid {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(d);
    uuid::Builder::from_custom_bytes(b).into_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vv(pairs: &[(u8, u64)]) -> VersionVector {
        VersionVector(pairs.iter().map(|(d, c)| ([*d; 8], *c)).collect())
    }

    fn rec(v: VersionVector) -> Record {
        Record { id: Uuid::nil(), kind: RecordKind::Entry, vv: v, deleted: false, blob: vec![] }
    }

    #[test]
    fn vv_compare() {
        assert_eq!(vv(&[(1, 1)]).compare(&vv(&[(1, 1)])), Some(Ordering::Equal));
        assert!(vv(&[(1, 2)]).dominates(&vv(&[(1, 1)])));
        assert!(vv(&[(1, 1), (2, 1)]).dominates(&vv(&[(1, 1)])));
        assert_eq!(vv(&[(1, 1)]).compare(&vv(&[(2, 1)])), None);
        assert!(vv(&[]).ge(&vv(&[])));
    }

    #[test]
    fn vv_merge_and_increment() {
        let mut a = vv(&[(1, 3), (2, 1)]);
        a.merge(&vv(&[(2, 5), (3, 1)]));
        assert_eq!(a, vv(&[(1, 3), (2, 5), (3, 1)]));
        a.increment([1; 8]);
        assert_eq!(a.get(&[1; 8]), 4);
    }

    #[test]
    fn merge_rule() {
        let mut l = vec![rec(vv(&[(1, 1)]))];
        // dominated incoming ignored
        assert!(!merge_sibling(&mut l, rec(vv(&[(1, 1)]))));
        // newer replaces
        assert!(merge_sibling(&mut l, rec(vv(&[(1, 2)]))));
        assert_eq!(l.len(), 1);
        // concurrent -> conflict (2 siblings)
        assert!(merge_sibling(&mut l, rec(vv(&[(1, 1), (2, 1)]))));
        assert_eq!(l.len(), 2);
        // resolution dominating both collapses to one
        assert!(merge_sibling(&mut l, rec(vv(&[(1, 2), (2, 2)]))));
        assert_eq!(l.len(), 1);
    }
}
