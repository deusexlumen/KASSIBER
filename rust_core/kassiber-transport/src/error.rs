use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Invalid dictionary: {0}")]
    InvalidDictionary(String),
    #[error("Unknown word: {0}")]
    UnknownWord(String),
    #[error("Invalid word index: {0}")]
    InvalidIndex(u16),
    #[error("Invalid frame type: {0:#04x}")]
    InvalidFrameType(u8),
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),
    #[error("Checksum mismatch: expected {expected}, computed {computed}")]
    ChecksumMismatch { expected: u32, computed: u32 },
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("Missing end marker")]
    MissingEndMarker,
    #[error("No data")]
    NoData,
}
