use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vault is locked")]
    Locked,
    #[error("no vault on this device")]
    NoVault,
    #[error("vault already exists")]
    VaultExists,
    #[error("wrong master password")]
    WrongPassword,
    #[error("decryption failed")]
    Decrypt,
    #[error("not found")]
    NotFound,
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("encoding: {0}")]
    Encode(#[from] postcard::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(String),
}

pub type Result<T> = std::result::Result<T, Error>;
