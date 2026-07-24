//! Transport codec: deflate compression → framing → dictionary encoding.
//!
//! Note on the bit packing: at 11 bits per word the index stream is not
//! byte-aligned, so decoding can yield up to one trailing padding byte. Every
//! frame is therefore prefixed with a 4-byte little-endian length before
//! packing, and decoding truncates to that length.

use crate::dictionary::{Bip39Dictionary, WordDictionary};
use crate::error::TransportError;
use crate::framing::{Chunker, Frame};

pub type Result<T> = std::result::Result<T, TransportError>;

/// Maximum decompressed payload size. Deflate bombs from untrusted carriers
/// must not be able to exhaust memory.
pub const MAX_DECOMPRESSED_SIZE: usize = 1024 * 1024; // 1 MiB

/// Length prefix prepended to each frame before word-index packing.
const LEN_PREFIX: usize = 4;

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub max_chunk_size: usize,
    pub dictionary: Bip39Dictionary,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 2048,
            dictionary: Bip39Dictionary::english(),
        }
    }
}

pub struct TransportCodec {
    config: TransportConfig,
    chunker: Chunker,
}

#[derive(Debug, Clone)]
pub struct EncodedPacket {
    pub sentence: String,
    pub raw_indices: Vec<u16>,
}

pub const KASSIBER_MARKER: &str = "<<<KASSIBER>>>";

impl TransportCodec {
    pub fn new(config: TransportConfig) -> Self {
        let chunker = Chunker::new(config.max_chunk_size);
        Self { config, chunker }
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<EncodedPacket>> {
        let compressed = compress(data)?;
        let frames = self.chunker.chunk(&compressed);
        frames
            .into_iter()
            .map(|frame| {
                let frame_bytes = frame.to_bytes();
                let mut buf = Vec::with_capacity(LEN_PREFIX + frame_bytes.len());
                buf.extend_from_slice(&(frame_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(&frame_bytes);
                let indices = bytes_to_word_indices(&buf, &self.config.dictionary)?;
                let sentence = self.config.dictionary.to_natural_sentence(&indices);
                Ok(EncodedPacket {
                    sentence,
                    raw_indices: indices,
                })
            })
            .collect()
    }

    pub fn decode(&self, packets: &[EncodedPacket]) -> Result<Vec<u8>> {
        if packets.is_empty() {
            return Err(TransportError::NoData);
        }
        let mut frames: Vec<Frame> = packets
            .iter()
            .map(|p| {
                let indices = self.config.dictionary.from_natural_sentence(&p.sentence)?;
                let packed = word_indices_to_bytes(&indices, &self.config.dictionary)?;
                if packed.len() < LEN_PREFIX {
                    return Err(TransportError::InvalidFrame(
                        "Packet shorter than length prefix".into(),
                    ));
                }
                let frame_len =
                    u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
                if packed.len() < LEN_PREFIX + frame_len {
                    return Err(TransportError::InvalidFrame(
                        "Packet truncated (declared frame length exceeds data)".into(),
                    ));
                }
                Frame::from_bytes(&packed[LEN_PREFIX..LEN_PREFIX + frame_len])
            })
            .collect::<Result<Vec<_>>>()?;
        let compressed = Chunker::reassemble(&mut frames)?;
        decompress(&compressed)
    }

    pub fn encode_single(&self, data: &[u8]) -> Result<String> {
        let packets = self.encode(data)?;
        let sentences: Vec<String> = packets.into_iter().map(|p| p.sentence).collect();
        Ok(format!(
            "{}\n{}\n{}",
            KASSIBER_MARKER,
            sentences.join("\n"),
            KASSIBER_MARKER
        ))
    }

    pub fn decode_from_carrier(&self, text: &str) -> Result<Option<Vec<u8>>> {
        let start = match text.find(KASSIBER_MARKER) {
            Some(pos) => pos + KASSIBER_MARKER.len(),
            None => return Ok(None),
        };
        let end = match text[start..].find(KASSIBER_MARKER) {
            Some(pos) => start + pos,
            None => return Err(TransportError::MissingEndMarker),
        };
        let sentences: Vec<String> = text[start..end]
            .lines()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if sentences.is_empty() {
            return Ok(None);
        }
        let packets: Vec<_> = sentences
            .into_iter()
            .map(|s| EncodedPacket {
                sentence: s,
                raw_indices: vec![],
            })
            .collect();
        self.decode(&packets).map(Some)
    }

    pub fn detect_kassiber(text: &str) -> bool {
        text.contains(KASSIBER_MARKER)
    }
}

impl Default for TransportCodec {
    fn default() -> Self {
        Self::new(TransportConfig::default())
    }
}

fn bytes_to_word_indices(data: &[u8], dict: &dyn WordDictionary) -> Result<Vec<u16>> {
    let bits = dict.bits_per_word();
    let mask = (1u16 << bits) - 1;
    let mut indices = Vec::with_capacity(data.len() * 8 / bits as usize + 1);
    let mut bit_buffer: u64 = 0;
    let mut bit_count: u8 = 0;
    for &byte in data {
        bit_buffer |= (byte as u64) << bit_count;
        bit_count += 8;
        while bit_count >= bits {
            indices.push((bit_buffer & (mask as u64)) as u16);
            bit_buffer >>= bits;
            bit_count -= bits;
        }
    }
    if bit_count > 0 {
        indices.push((bit_buffer & (mask as u64)) as u16);
    }
    Ok(indices)
}

fn word_indices_to_bytes(indices: &[u16], dict: &dyn WordDictionary) -> Result<Vec<u8>> {
    let bits = dict.bits_per_word();
    let mut bytes = Vec::with_capacity(indices.len() * bits as usize / 8 + 1);
    let mut bit_buffer: u64 = 0;
    let mut bit_count: u8 = 0;
    for &idx in indices {
        if idx >= dict.size() {
            return Err(TransportError::InvalidIndex(idx));
        }
        bit_buffer |= (idx as u64) << bit_count;
        bit_count += bits;
        while bit_count >= 8 {
            bytes.push((bit_buffer & 0xFF) as u8);
            bit_buffer >>= 8;
            bit_count -= 8;
        }
    }
    if bit_count > 0 {
        bytes.push((bit_buffer & 0xFF) as u8);
    }
    Ok(bytes)
}

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .map_err(|e| TransportError::Compression(format!("Compress: {:?}", e)))?;
    encoder
        .finish()
        .map_err(|e| TransportError::Compression(format!("Compress finish: {:?}", e)))
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let decoder = DeflateDecoder::new(data);
    // Hard cap on the decompressed size: read at most MAX+1 bytes and treat
    // anything beyond MAX as a decompression bomb.
    let mut limited = decoder.take(MAX_DECOMPRESSED_SIZE as u64 + 1);
    let mut result = Vec::new();
    limited
        .read_to_end(&mut result)
        .map_err(|e| TransportError::Compression(format!("Decompress: {:?}", e)))?;
    if result.len() > MAX_DECOMPRESSED_SIZE {
        return Err(TransportError::Compression(format!(
            "Decompressed size exceeds limit of {} bytes",
            MAX_DECOMPRESSED_SIZE
        )));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_small() {
        let codec = TransportCodec::default();
        let data = b"Hello, KASSIBER!";
        let packets = codec.encode(data).unwrap();
        assert_eq!(codec.decode(&packets).unwrap(), data);
    }

    #[test]
    fn test_roundtrip_large() {
        let codec = TransportCodec::default();
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        assert_eq!(codec.decode(&codec.encode(&data).unwrap()).unwrap(), data);
    }

    #[test]
    fn test_roundtrip_every_length() {
        // Exercises the 11-bit packing edge cases around the length prefix.
        let codec = TransportCodec::default();
        for len in 0..64usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let packets = codec.encode(&data).unwrap();
            assert_eq!(codec.decode(&packets).unwrap(), data, "len {}", len);
        }
    }

    #[test]
    fn test_carrier_format() {
        let codec = TransportCodec::default();
        let encoded = codec.encode_single(b"Secret message").unwrap();
        assert!(encoded.starts_with(KASSIBER_MARKER));
        assert!(encoded.ends_with(KASSIBER_MARKER));
        assert_eq!(
            codec.decode_from_carrier(&encoded).unwrap().unwrap(),
            b"Secret message"
        );
    }

    #[test]
    fn test_detect_kassiber() {
        assert!(TransportCodec::detect_kassiber("Hello <<<KASSIBER>>> world"));
        assert!(!TransportCodec::detect_kassiber("Hello world"));
    }

    #[test]
    fn test_decompression_bomb_rejected() {
        let codec = TransportCodec::default();
        // 2 MiB of zeros compresses to a few KB — well under the chunk limit,
        // but far beyond MAX_DECOMPRESSED_SIZE once inflated.
        let bomb_raw = vec![0u8; 2 * MAX_DECOMPRESSED_SIZE];
        let compressed = compress(&bomb_raw).unwrap();
        assert!(compressed.len() < MAX_DECOMPRESSED_SIZE);
        let chunker = Chunker::new(codec.config.max_chunk_size);
        let packets: Vec<EncodedPacket> = chunker
            .chunk(&compressed)
            .iter()
            .map(|f| {
                let fb = f.to_bytes();
                let mut buf = (fb.len() as u32).to_le_bytes().to_vec();
                buf.extend_from_slice(&fb);
                let idx = bytes_to_word_indices(&buf, &codec.config.dictionary).unwrap();
                EncodedPacket {
                    sentence: codec.config.dictionary.to_natural_sentence(&idx),
                    raw_indices: idx,
                }
            })
            .collect();
        assert!(codec.decode(&packets).is_err());
    }

    #[test]
    fn test_decompressed_size_at_limit_ok() {
        // Exactly at the limit must still decode.
        let data = vec![7u8; MAX_DECOMPRESSED_SIZE];
        assert_eq!(decompress(&compress(&data).unwrap()).unwrap(), data);
    }
}
