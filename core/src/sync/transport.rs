//! Noise-encrypted framed transport over TCP.
//!
//! Wire format: a 5-byte cleartext preamble (`PPv1` + mode), then for sync mode the
//! initiator's 8-byte device id (already public via mDNS) so the responder can pick the
//! peer's static key for Noise_KK. Every later byte is a Noise message prefixed by a
//! u16 BE length. Application frames are `u32 BE length || postcard payload`, split
//! across Noise messages of at most 65535 bytes. There is no plaintext fallback.
use crate::identity::{NOISE_KK, NOISE_XKPSK3};
use crate::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use snow::{HandshakeState, TransportState};
use std::io::{Read, Write};
use std::net::TcpStream;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"PPv1";
pub const MODE_SYNC: u8 = 0;
pub const MODE_PAIR: u8 = 1;
const NOISE_MAX: usize = 65535;
const TAG: usize = 16;
const MAX_FRAME: usize = 64 * 1024 * 1024;

fn noise_err(e: snow::Error) -> Error {
    Error::Noise(e.to_string())
}

fn write_noise_msg(s: &mut TcpStream, m: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(2 + m.len());
    buf.extend_from_slice(&(m.len() as u16).to_be_bytes());
    buf.extend_from_slice(m);
    s.write_all(&buf)?;
    Ok(())
}

fn read_noise_msg(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut l = [0u8; 2];
    s.read_exact(&mut l)?;
    let mut m = vec![0u8; u16::from_be_bytes(l) as usize];
    s.read_exact(&mut m)?;
    Ok(m)
}

/// Runs a Noise handshake to completion over `s`.
fn handshake(s: &mut TcpStream, mut hs: HandshakeState) -> Result<HandshakeState> {
    let mut buf = vec![0u8; NOISE_MAX];
    let mut pl = vec![0u8; NOISE_MAX];
    while !hs.is_handshake_finished() {
        if hs.is_my_turn() {
            let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
            write_noise_msg(s, &buf[..n])?;
        } else {
            let m = read_noise_msg(s)?;
            hs.read_message(&m, &mut pl).map_err(noise_err)?;
        }
    }
    Ok(hs)
}

pub struct NoiseStream {
    stream: TcpStream,
    noise: TransportState,
    rbuf: Vec<u8>,
    /// Handshake hash, used to derive the pairing verification code.
    pub handshake_hash: Vec<u8>,
    pub remote_static: [u8; 32],
}

impl NoiseStream {
    fn finish(stream: TcpStream, hs: HandshakeState) -> Result<Self> {
        let handshake_hash = hs.get_handshake_hash().to_vec();
        let remote_static: [u8; 32] = hs
            .get_remote_static()
            .ok_or_else(|| Error::Noise("no remote static".into()))?
            .try_into()
            .map_err(|_| Error::Noise("bad remote static".into()))?;
        let noise = hs.into_transport_mode().map_err(noise_err)?;
        Ok(Self { stream, noise, rbuf: Vec::new(), handshake_hash, remote_static })
    }

    /// Initiator, sync mode (Noise_KK with a paired device).
    pub fn connect_kk(mut s: TcpStream, my_secret: &[u8; 32], my_id: &[u8; 8], peer_pub: &[u8; 32]) -> Result<Self> {
        let mut pre = MAGIC.to_vec();
        pre.push(MODE_SYNC);
        pre.extend_from_slice(my_id);
        s.write_all(&pre)?;
        let hs = snow::Builder::new(NOISE_KK.parse().unwrap())
            .local_private_key(my_secret)
            .and_then(|b| b.remote_public_key(peer_pub))
            .and_then(|b| b.build_initiator())
            .map_err(noise_err)?;
        let hs = handshake(&mut s, hs)?;
        Self::finish(s, hs)
    }

    /// Responder, sync mode. The preamble has been consumed already.
    pub fn accept_kk(mut s: TcpStream, my_secret: &[u8; 32], peer_pub: &[u8; 32]) -> Result<Self> {
        let hs = snow::Builder::new(NOISE_KK.parse().unwrap())
            .local_private_key(my_secret)
            .and_then(|b| b.remote_public_key(peer_pub))
            .and_then(|b| b.build_responder())
            .map_err(noise_err)?;
        let hs = handshake(&mut s, hs)?;
        Self::finish(s, hs)
    }

    /// Initiator, pairing (Noise_XKpsk3, PSK = one-time token from the QR code).
    pub fn connect_xkpsk3(mut s: TcpStream, my_secret: &[u8; 32], peer_pub: &[u8; 32], psk: &[u8; 32]) -> Result<Self> {
        let mut pre = MAGIC.to_vec();
        pre.push(MODE_PAIR);
        s.write_all(&pre)?;
        let hs = snow::Builder::new(NOISE_XKPSK3.parse().unwrap())
            .local_private_key(my_secret)
            .and_then(|b| b.remote_public_key(peer_pub))
            .and_then(|b| b.psk(3, psk))
            .and_then(|b| b.build_initiator())
            .map_err(noise_err)?;
        let hs = handshake(&mut s, hs)?;
        Self::finish(s, hs)
    }

    pub fn accept_xkpsk3(mut s: TcpStream, my_secret: &[u8; 32], psk: &[u8; 32]) -> Result<Self> {
        let hs = snow::Builder::new(NOISE_XKPSK3.parse().unwrap())
            .local_private_key(my_secret)
            .and_then(|b| b.psk(3, psk))
            .and_then(|b| b.build_responder())
            .map_err(noise_err)?;
        let hs = handshake(&mut s, hs)?;
        Self::finish(s, hs)
    }

    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr().ok()
    }

    pub fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let payload = Zeroizing::new(postcard::to_allocvec(msg)?);
        let mut frame = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let mut out = vec![0u8; NOISE_MAX];
        for chunk in frame.chunks(NOISE_MAX - TAG) {
            let n = self.noise.write_message(chunk, &mut out).map_err(noise_err)?;
            write_noise_msg(&mut self.stream, &out[..n])?;
        }
        Ok(())
    }

    fn fill(&mut self, want: usize) -> Result<()> {
        let mut pl = vec![0u8; NOISE_MAX];
        while self.rbuf.len() < want {
            let m = read_noise_msg(&mut self.stream)?;
            let n = self.noise.read_message(&m, &mut pl).map_err(noise_err)?;
            self.rbuf.extend_from_slice(&pl[..n]);
        }
        Ok(())
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.fill(4)?;
        let len = u32::from_be_bytes(self.rbuf[..4].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(Error::Protocol("frame too large".into()));
        }
        self.fill(4 + len)?;
        let payload = Zeroizing::new(self.rbuf[4..4 + len].to_vec());
        self.rbuf.drain(..4 + len);
        Ok(postcard::from_bytes(&payload)?)
    }
}

/// Reads the cleartext preamble on an accepted connection.
/// Returns (mode, Some(device_id) for sync mode).
pub fn read_preamble(s: &mut TcpStream) -> Result<(u8, Option<[u8; 8]>)> {
    let mut p = [0u8; 5];
    s.read_exact(&mut p)?;
    if &p[..4] != MAGIC {
        return Err(Error::Protocol("bad magic".into()));
    }
    match p[4] {
        MODE_SYNC => {
            let mut d = [0u8; 8];
            s.read_exact(&mut d)?;
            Ok((MODE_SYNC, Some(d)))
        }
        MODE_PAIR => Ok((MODE_PAIR, None)),
        _ => Err(Error::Protocol("bad mode".into())),
    }
}
