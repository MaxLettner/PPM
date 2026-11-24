//! LAN sync: Noise transport, state-based exchange, pairing and mDNS discovery.
pub mod approval;
pub mod discovery;
pub mod exchange;
pub mod node;
pub mod pairing;
pub mod transport;

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_PORT: u16 = 47823;
pub const SERVICE_TYPE: &str = "_peerpass._tcp.local.";
