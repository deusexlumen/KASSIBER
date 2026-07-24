use crate::error::TransportError;
pub type Result<T> = std::result::Result<T, TransportError>;

pub const MAX_CHUNK_SIZE: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    First = 0x01,
    Continuation = 0x02,
    Last = 0x03,
    Single = 0x04,
}

impl FrameType {
    pub fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::First), 0x02 => Ok(Self::Continuation),
            0x03 => Ok(Self::Last), 0x04 => Ok(Self::Single),
            _ => Err(TransportError::InvalidFrameType(byte)),
        }
    }
    pub fn is_first(&self) -> bool { matches!(self, Self::First | Self::Single) }
    pub fn is_last(&self) -> bool { matches!(self, Self::Last | Self::Single) }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub sequence: u16,
    pub total_chunks: u16,
    pub payload: Vec<u8>,
    pub checksum: u32,
}

impl Frame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + self.payload.len());
        buf.push(self.frame_type as u8);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.total_chunks.to_le_bytes());
        buf.extend_from_slice(&self.checksum.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 9 { return Err(TransportError::InvalidFrame("Frame too short".into())); }
        let frame_type = FrameType::from_u8(data[0])?;
        let sequence = u16::from_le_bytes([data[1], data[2]]);
        let total_chunks = u16::from_le_bytes([data[3], data[4]]);
        let checksum = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
        let payload = data[9..].to_vec();
        let computed = crc32(&payload);
        if computed != checksum { return Err(TransportError::ChecksumMismatch { expected: checksum, computed }); }
        Ok(Self { frame_type, sequence, total_chunks, payload, checksum })
    }
}

pub struct Chunker { max_chunk_size: usize }

impl Chunker {
    pub fn new(max_chunk_size: usize) -> Self { Self { max_chunk_size: max_chunk_size.min(MAX_CHUNK_SIZE) } }

    pub fn chunk(&self, data: &[u8]) -> Vec<Frame> {
        let payload_limit = self.max_chunk_size.saturating_sub(9);
        if data.len() <= payload_limit {
            return vec![Frame { frame_type: FrameType::Single, sequence: 0, total_chunks: 1, payload: data.to_vec(), checksum: crc32(data) }];
        }
        let total = (data.len() + payload_limit - 1) / payload_limit;
        let total_u16 = total.min(u16::MAX as usize) as u16;
        data.chunks(payload_limit).enumerate().map(|(i, chunk)| {
            let frame_type = if i == 0 { FrameType::First } else if i == total - 1 { FrameType::Last } else { FrameType::Continuation };
            Frame { frame_type, sequence: i as u16, total_chunks: total_u16, payload: chunk.to_vec(), checksum: crc32(chunk) }
        }).collect()
    }

    /// Reassemble frames into the original payload, with full validation:
    /// consistent `total_chunks`, exactly one chunk per sequence number
    /// (no duplicates, no gaps) and the expected frame-type sequence
    /// (Single, or First → Continuation* → Last).
    pub fn reassemble(frames: &mut [Frame]) -> Result<Vec<u8>> {
        if frames.is_empty() {
            return Err(TransportError::InvalidFrame("No frames".into()));
        }
        frames.sort_by_key(|f| f.sequence);

        let total = frames[0].total_chunks;
        if total == 0 {
            return Err(TransportError::InvalidFrame("total_chunks is zero".into()));
        }
        if frames.len() != total as usize {
            return Err(TransportError::InvalidFrame(format!(
                "Expected {} chunks, got {}",
                total,
                frames.len()
            )));
        }
        for (i, f) in frames.iter().enumerate() {
            if f.total_chunks != total {
                return Err(TransportError::InvalidFrame(
                    "Inconsistent total_chunks across frames".into(),
                ));
            }
            if f.sequence != i as u16 {
                return Err(TransportError::InvalidFrame(format!(
                    "Duplicate or missing chunk at sequence {}",
                    i
                )));
            }
            let expected = if total == 1 {
                FrameType::Single
            } else if i == 0 {
                FrameType::First
            } else if i == total as usize - 1 {
                FrameType::Last
            } else {
                FrameType::Continuation
            };
            if f.frame_type != expected {
                return Err(TransportError::InvalidFrame(format!(
                    "Unexpected frame type {:?} at sequence {} (expected {:?})",
                    f.frame_type, i, expected
                )));
            }
        }
        Ok(frames.iter().flat_map(|f| f.payload.clone()).collect())
    }
}

impl Default for Chunker { fn default() -> Self { Self::new(MAX_CHUNK_SIZE) } }

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB88320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_frame() {
        let frames = Chunker::default().chunk(b"hello");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"hello");
    }

    #[test]
    fn test_multi_frame() {
        let data = vec![0u8; 50];
        let frames = Chunker::new(20).chunk(&data);
        assert!(frames.len() > 1);
        assert_eq!(frames[0].frame_type, FrameType::First);
        assert_eq!(frames.last().unwrap().frame_type, FrameType::Last);
    }

    #[test]
    fn test_reassemble() {
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let mut frames = Chunker::new(20).chunk(&data);
        assert_eq!(Chunker::reassemble(&mut frames).unwrap(), data);
    }

    #[test]
    fn test_reassemble_out_of_order_ok() {
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let mut frames = Chunker::new(20).chunk(&data);
        frames.reverse();
        assert_eq!(Chunker::reassemble(&mut frames).unwrap(), data);
    }

    #[test]
    fn test_reassemble_rejects_missing_chunk() {
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let frames = Chunker::new(20).chunk(&data);
        let mut truncated: Vec<Frame> = frames.into_iter().skip(1).collect();
        assert!(Chunker::reassemble(&mut truncated).is_err());
    }

    #[test]
    fn test_reassemble_rejects_duplicate_chunk() {
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let frames = Chunker::new(20).chunk(&data);
        let mut dup = frames.clone();
        dup.push(frames[1].clone());
        assert!(Chunker::reassemble(&mut dup).is_err());
    }

    #[test]
    fn test_reassemble_rejects_wrong_frame_type() {
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let mut frames = Chunker::new(20).chunk(&data);
        // Corrupt: middle chunk claims to be the Last chunk.
        let mid = frames.len() / 2;
        frames[mid].frame_type = FrameType::Last;
        assert!(Chunker::reassemble(&mut frames).is_err());
    }
}
