//! Per-device X25519 static keypair used for Noise. Persisting it is the platform's job
//! (Linux: 0600 file; Android: Keystore-wrapped).
use crate::model::{device_id_from_pubkey, DeviceId};
use crate::{Error, Result};
use zeroize::Zeroizing;

pub const NOISE_KK: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_XKPSK3: &str = "Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s";

pub struct Identity {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        let kp = snow::Builder::new(NOISE_KK.parse().unwrap()).generate_keypair().expect("keygen");
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&kp.private);
        let mut private = kp.private;
        zeroize::Zeroize::zeroize(&mut private);
        Self { secret, public: kp.public.try_into().unwrap() }
    }

    /// Rebuilds the identity from its 32-byte secret.
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        let s: [u8; 32] = secret.try_into().map_err(|_| Error::Invalid("identity key length".into()))?;
        let public = x25519_public(&s);
        Ok(Self { secret: Zeroizing::new(s), public })
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn device_id(&self) -> DeviceId {
        device_id_from_pubkey(&self.public)
    }
}

/// Derives the X25519 public key by running a one-off Noise "N"-less trick is not
/// available in snow, so we use the curve25519 base-point multiplication from snow's
/// own resolver.
fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    let mut dh = DefaultResolver.resolve_dh(&snow::params::DHChoice::Curve25519).expect("x25519");
    dh.set(secret);
    dh.pubkey().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a = Identity::generate();
        let b = Identity::from_secret(a.secret()).unwrap();
        assert_eq!(a.public(), b.public());
        assert_eq!(a.device_id(), b.device_id());
    }
}
