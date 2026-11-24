//! peerpass core: data model, crypto, storage, sync, pairing, TOTP, import.
pub mod crypto;
pub mod domain;
pub mod error;
pub mod generator;
pub mod identity;
pub mod import;
pub mod model;
pub mod storage;
pub mod sync;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
