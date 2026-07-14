//! KASSIBER Transport Layer
//!
//! Dictionary Transport Codec:
//! Framing → Chunking (≤ 2 KB) → Dictionary Encoder

pub mod codec;
pub mod dictionary;
pub mod framing;

pub use codec::{TransportCodec, TransportConfig};
pub use dictionary::{Bip39Dictionary, WordDictionary};
pub use framing::{Chunker, Frame, FrameType, MAX_CHUNK_SIZE};
