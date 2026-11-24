//! Pairing: QR/text offer, Noise_XKpsk3 with a one-time token, 6-digit confirmation.
//! The new device only receives the vault header; it still needs the master password.
use super::exchange::Msg;
use super::transport::NoiseStream;
use crate::model::{device_id_from_pubkey, DeviceId, DeviceInfo};
use crate::vault::{now, Vault};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const OFFER_TTL_SECS: i64 = 300;
const TEXT_PREFIX: &str = "PEERPASS1-";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingOffer {
    pub v: u32,
    pub vault_id: Uuid,
    pub device_pubkey: [u8; 32],
    pub addrs: Vec<String>,
    pub port: u16,
    pub token: [u8; 32],
    pub expires: i64,
}

impl Drop for PairingOffer {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

impl PairingOffer {
    /// Base32 text; the QR code encodes exactly this string.
    pub fn to_text(&self) -> String {
        let b = postcard::to_allocvec(self).expect("offer encodes");
        format!("{TEXT_PREFIX}{}", data_encoding::BASE32_NOPAD.encode(&b))
    }

    pub fn from_text(s: &str) -> Result<Self> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
        let body = s.strip_prefix(TEXT_PREFIX).ok_or_else(|| Error::Invalid("not a peerpass pairing code".into()))?;
        let b = data_encoding::BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| Error::Invalid("pairing code is corrupted".into()))?;
        let o: Self = postcard::from_bytes(&b)?;
        if o.v != 1 {
            return Err(Error::Invalid("unsupported pairing code version".into()));
        }
        Ok(o)
    }
}

/// 6-digit code shown on both screens, derived from the Noise handshake hash.
pub fn verification_code(handshake_hash: &[u8]) -> String {
    let n = u32::from_be_bytes(handshake_hash[..4].try_into().unwrap()) % 1_000_000;
    format!("{n:06}")
}

pub struct PairingSession {
    pub token: Zeroizing<[u8; 32]>,
    pub expires: i64,
}

/// Non-loopback IPv4 addresses of this machine (for the pairing offer).
pub fn local_ipv4_addrs() -> Vec<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(a) if !a.is_link_local() => Some(a.to_string()),
            _ => None,
        })
        .collect()
}

/// Existing device: creates a new offer (requires an unlocked vault).
pub fn create_offer(v: &Vault, addrs: Vec<String>, port: u16) -> Result<(PairingOffer, PairingSession)> {
    if !v.is_unlocked() {
        return Err(Error::Locked);
    }
    let token = crate::crypto::random_bytes::<32>();
    let expires = now() + OFFER_TTL_SECS;
    let offer = PairingOffer { v: 1, vault_id: v.vault_id()?, device_pubkey: *v.identity().public(), addrs, port, token, expires };
    Ok((offer, PairingSession { token: Zeroizing::new(token), expires }))
}

/// Existing device: handles an incoming MODE_PAIR connection (preamble consumed).
/// `approve(name, code)` asks the user. Returns the new device on success.
pub fn handle_incoming(
    vault: &Mutex<Vault>,
    stream: TcpStream,
    session: &Mutex<Option<PairingSession>>,
    approve: &(dyn Fn(&str, &str) -> bool + Send + Sync),
) -> Result<Option<(DeviceId, String)>> {
    let token = match &*session.lock().unwrap() {
        Some(s) if s.expires > now() => s.token.clone(),
        _ => return Err(Error::Protocol("no active pairing session".into())),
    };
    let secret = Zeroizing::new(*vault.lock().unwrap().identity().secret());
    let peer_ip = stream.peer_addr()?.ip();
    let mut ns = NoiseStream::accept_xkpsk3(stream, &secret, &token)?;
    // Token is single-use once a handshake with it succeeded.
    *session.lock().unwrap() = None;
    let (name, port) = match ns.recv()? {
        Msg::PairRequest { name, port } => (name, port),
        _ => return Err(Error::Protocol("expected PairRequest".into())),
    };
    let code = verification_code(&ns.handshake_hash);
    if !approve(&name, &code) {
        ns.send(&Msg::PairReject)?;
        return Ok(None);
    }
    let pubkey = ns.remote_static;
    let d = device_id_from_pubkey(&pubkey);
    let (my_name, header) = {
        let mut v = vault.lock().unwrap();
        v.add_device(DeviceInfo { pubkey, name: name.clone() })?;
        v.db.set_peer_addr(&d, &SocketAddr::new(peer_ip, port).to_string())?;
        let my_name = v.db.get_meta("device_name")?.map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        (my_name, v.db.header()?.ok_or(Error::NoVault)?)
    };
    ns.send(&Msg::PairAccept { name: my_name, header })?;
    Ok(Some((d, name)))
}

/// New device: joins using an offer. `on_code` displays the verification code while the
/// other device asks its user to accept. Returns the existing device's name.
pub fn join(
    vault: &Mutex<Vault>,
    offer: &PairingOffer,
    my_name: &str,
    my_port: u16,
    on_code: &dyn Fn(&str),
) -> Result<String> {
    if offer.expires < now() {
        return Err(Error::Invalid("pairing code expired".into()));
    }
    let secret = {
        let v = vault.lock().unwrap();
        if v.has_vault()? {
            return Err(Error::VaultExists);
        }
        Zeroizing::new(*v.identity().secret())
    };
    let mut last_err = Error::Invalid("no address in pairing code".into());
    for a in &offer.addrs {
        let addr: SocketAddr = match format!("{a}:{}", offer.port).parse() {
            Ok(x) => x,
            Err(_) => continue,
        };
        let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(e) => {
                last_err = e.into();
                continue;
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(180)))?;
        let mut ns = NoiseStream::connect_xkpsk3(stream, &secret, &offer.device_pubkey, &offer.token)?;
        on_code(&verification_code(&ns.handshake_hash));
        ns.send(&Msg::PairRequest { name: my_name.to_string(), port: my_port })?;
        return match ns.recv()? {
            Msg::PairAccept { name, header } => {
                if header.vault_id != offer.vault_id {
                    return Err(Error::Protocol("vault id mismatch".into()));
                }
                let v = &mut vault.lock().unwrap();
                v.apply_header(header)?;
                let d = device_id_from_pubkey(&offer.device_pubkey);
                v.db.upsert_peer(&d, &offer.device_pubkey, &name)?;
                v.db.set_peer_addr(&d, &addr.to_string())?;
                v.db.set_meta("device_name", my_name.as_bytes())?;
                Ok(name)
            }
            Msg::PairReject => Err(Error::Invalid("the other device rejected pairing".into())),
            _ => Err(Error::Protocol("unexpected pairing reply".into())),
        };
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_text_roundtrip() {
        let o = PairingOffer {
            v: 1,
            vault_id: Uuid::now_v7(),
            device_pubkey: [7; 32],
            addrs: vec!["192.168.1.10".into()],
            port: 47823,
            token: [9; 32],
            expires: 123,
        };
        let t = o.to_text();
        assert_eq!(PairingOffer::from_text(&t.to_lowercase()).unwrap(), o);
        assert!(PairingOffer::from_text("garbage").is_err());
    }
}
