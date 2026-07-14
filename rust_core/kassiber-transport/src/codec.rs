use crate::dictionary::{Bip39Dictionary, WordDictionary};
use crate::error::TransportError;
use crate::framing::{Chunker, Frame};

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub max_chunk_size: usize,
    pub dictionary: Bip39Dictionary,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self { max_chunk_size: 2048, dictionary: Bip39Dictionary::english() }
    }
}

pub struct TransportCodec { config: TransportConfig, chunker: Chunker }

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
        frames.into_iter().map(|frame| {
            let frame_bytes = frame.to_bytes();
            let indices = bytes_to_word_indices(&frame_bytes, &self.config.dictionary)?;
            let sentence = self.config.dictionary.to_natural_sentence(&indices);
            Ok(EncodedPacket { sentence, raw_indices: indices })
        }).collect()
    }

    pub fn decode(&self, packets: &[EncodedPacket]) -> Result<Vec<u8>> {
        if packets.is_empty() { return Err(TransportError::NoData); }
        let mut frames: Vec<Frame> = packets.iter().map(|p| {
            let indices = self.config.dictionary.from_natural_sentence(&p.sentence)?;
            let frame_bytes = word_indices_to_bytes(&indices, &self.config.dictionary)?;
            Frame::from_bytes(&frame_bytes)
        }).collect::<Result<Vec<_>>>()?;
        let compressed = Chunker::reassemble(&mut frames)?;
        decompress(&compressed)
    }

    pub fn encode_single(&self, data: &[u8]) -> Result<String> {
        let packets = self.encode(data)?;
        let sentences: Vec<String> = packets.into_iter().map(|p| p.sentence).collect();
        Ok(format!("{}\n{}\n{}", KASSIBER_MARKER, sentences.join("\n"), KASSIBER_MARKER))
    }

    pub fn decode_from_carrier(&self, text: &str) -> Result<Option<Vec<u8>>> {
        let start = match text.find(KASSIBER_MARKER) { Some(pos) => pos + KASSIBER_MARKER.len(), None => return Ok(None) };
        let end = match text[start..].find(KASSIBER_MARKER) { Some(pos) => start + pos, None => return Err(TransportError::MissingEndMarker) };
        let sentences: Vec<String> = text[start..end].lines().map(|s| s.trim()).filter(|s| !s.is_empty()).map(String::from).collect();
        if sentences.is_empty() { return Ok(None); }
        let packets: Vec<_> = sentences.into_iter().map(|s| EncodedPacket { sentence: s, raw_indices: vec![] }).collect();
        self.decode(&packets).map(Some)
    }

    pub fn detect_kassiber(text: &str) -> bool { text.contains(KASSIBER_MARKER) }
}

impl Default for TransportCodec { fn default() -> Self { Self::new(TransportConfig::default()) } }

fn bytes_to_word_indices(data: &[u8], dict: &dyn WordDictionary) -> Result<Vec<u16>> {
    let bits = dict.bits_per_word();
    let mask = (1u16 << bits) - 1;
    let mut indices = Vec::with_capacity(data.len() * 8 / bits as usize);
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
    if bit_count > 0 { indices.push((bit_buffer & (mask as u64)) as u16); }
    Ok(indices)
}

fn word_indices_to_bytes(indices: &[u16], dict: &dyn WordDictionary) -> Result<Vec<u8>> {
    let bits = dict.bits_per_word();
    let mut bytes = Vec::with_capacity(indices.len() * bits as usize / 8);
    let mut bit_buffer: u64 = 0;
    let mut bit_count: u8 = 0;
    for &idx in indices {
        if idx >= dict.size() { return Err(TransportError::InvalidIndex(idx)); }
        bit_buffer |= (idx as u64) << bit_count;
        bit_count += bits;
        while bit_count >= 8 {
            bytes.push((bit_buffer & 0xFF) as u8);
            bit_buffer >>= 8;
            bit_count -= 8;
        }
    }
    if bit_count > 0 { bytes.push((bit_buffer & 0xFF) as u8); }
    Ok(bytes)
}

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).map_err(|e| TransportError::Compression(format!("Compress: {:?}", e)))?;
    encoder.finish().map_err(|e| TransportError::Compression(format!("Compress finish: {:?}", e)))
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).map_err(|e| TransportError::Compression(format!("Decompress: {:?}", e)))?;
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
    fn test_carrier_format() {
        let codec = TransportCodec::default();
        let encoded = codec.encode_single(b"Secret message").unwrap();
        assert!(encoded.starts_with(KASSIBER_MARKER));
        assert!(encoded.ends_with(KASSIBER_MARKER));
        assert_eq!(codec.decode_from_carrier(&encoded).unwrap().unwrap(), b"Secret message");
    }

    #[test]
    fn test_detect_kassiber() {
        assert!(TransportCodec::detect_kassiber("Hello <<<KASSIBER>>> world"));
        assert!(!TransportCodec::detect_kassiber("Hello world"));
    }
}
