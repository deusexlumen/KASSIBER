use thiserror::Error;

/// KASSIBER Krypto-Fehlertypen
#[derive(Debug, Error)]
pub enum KassiberError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Signature failed: {0}")]
    Signature(String),
    #[error("Signature verification failed")]
    SignatureVerification,
    #[error("Keystore error: {0}")]
    Keystore(String),
    #[error("Ratchet desynchronized: {0}")]
    RatchetDesync(String),
    #[error("Session reset required")]
    SessionResetRequired,
    #[error("Invalid session state: {0}")]
    InvalidSession(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("FFI error: {0}")]
    Ffi(String),
}

pub type Result<T> = std::result::Result<T, KassiberError>;
