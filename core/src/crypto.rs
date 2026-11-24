//! Thin wrappers over audited RustCrypto primitives. No custom constructions.
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;
const NONCE_LEN: usize = 24;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    b
}

pub fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    getrandom::fill(k.as_mut()).expect("OS RNG unavailable");
    k
}

/// Argon2id parameters, stored in the (synced) vault header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    /// Starting point from the spec: m=64 MiB, t=3, p=1.
    fn default() -> Self {
        Self { m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

pub fn derive_key(password: &[u8], salt: &[u8], p: &KdfParams) -> Result<Key> {
    let params = argon2::Params::new(p.m_kib, p.t, p.p, Some(32))
        .map_err(|e| Error::Invalid(format!("argon2 params: {e}")))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, out.as_mut())
        .map_err(|e| Error::Invalid(format!("argon2: {e}")))?;
    Ok(out)
}

/// XChaCha20-Poly1305 with a random nonce. Output: nonce || ciphertext+tag.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = XNonce::try_from(&nonce_bytes[..]).expect("24-byte nonce");
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("encryption cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN + 16 {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let nonce = XNonce::try_from(&data[..NONCE_LEN]).map_err(|_| Error::Decrypt)?;
    cipher
        .decrypt(&nonce, Payload { msg: &data[NONCE_LEN..], aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// BLAKE2s-256 hash.
pub fn blake2s(data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut h = blake2::Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = random_key();
        let ct = seal(&k, b"aad", b"secret");
        assert_eq!(&open(&k, b"aad", &ct).unwrap()[..], b"secret");
    }

    #[test]
    fn open_rejects_wrong_aad_key_or_tamper() {
        let k = random_key();
        let mut ct = seal(&k, b"aad", b"secret");
        assert!(open(&k, b"other", &ct).is_err());
        assert!(open(&random_key(), b"aad", &ct).is_err());
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(open(&k, b"aad", &ct).is_err());
    }

    #[test]
    fn kdf_is_deterministic() {
        let p = KdfParams { m_kib: 64, t: 1, p: 1 };
        let a = derive_key(b"pw", b"saltsaltsaltsalt", &p).unwrap();
        let b = derive_key(b"pw", b"saltsaltsaltsalt", &p).unwrap();
        let c = derive_key(b"pw2", b"saltsaltsaltsalt", &p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }
}
