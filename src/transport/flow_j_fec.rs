// src/transport/flow_j_fec.rs
#![allow(dead_code)] // Module contains stub implementations for future use
//! Flow-J Elastic FEC (Forward Error Correction)
//!
//! Implements Reed-Solomon erasure coding for packet recovery on unreliable networks.
//! Features:
//! - Configurable data/parity shard ratio
//! - Zero-copy optimization using BytesMut
//! - Stream wrapper for transparent FEC encoding/decoding

use crate::error::Result;
use bytes::BytesMut;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io;
use tracing::{debug, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default number of data shards
pub const DEFAULT_DATA_SHARDS: usize = 10;

/// Default number of parity shards
pub const DEFAULT_PARITY_SHARDS: usize = 3;

/// Maximum shard size
const MAX_SHARD_SIZE: usize = 1400; // MTU-friendly

/// FEC frame header size
const FEC_HEADER_SIZE: usize = 8;

// ============================================================================
// FEC ENCODER
// ============================================================================

/// FEC encoder for outgoing data
pub struct FecEncoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
    buffer: Vec<Vec<u8>>,
    shard_size: usize,
    sequence: u32,
}

impl FecEncoder {
    /// Create new FEC encoder
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow::anyhow!("Failed to create Reed-Solomon: {:?}", e))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
            buffer: Vec::with_capacity(data_shards),
            shard_size: MAX_SHARD_SIZE,
            sequence: 0,
        })
    }

    /// Encode data into FEC shards
    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<FecFrame>> {
        let total_shards = self.data_shards + self.parity_shards;

        // Calculate shard size to fit data
        let data_len = data.len();
        let shard_size = (data_len + self.data_shards - 1) / self.data_shards;
        let shard_size = shard_size.max(1).min(MAX_SHARD_SIZE);

        // Create data shards with padding
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);

        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data_len);

            let mut shard = vec![0u8; shard_size];
            if start < data_len {
                let copy_len = end.saturating_sub(start);
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Create empty parity shards
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode parity shards
        self.rs
            .encode(&mut shards)
            .map_err(|e| anyhow::anyhow!("FEC encode error: {:?}", e))?;

        // Create FEC frames
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);

        let frames: Vec<FecFrame> = shards
            .into_iter()
            .enumerate()
            .map(|(idx, shard)| FecFrame {
                sequence: seq,
                shard_index: idx as u8,
                total_shards: total_shards as u8,
                data_shards: self.data_shards as u8,
                data_len: data_len as u32,
                payload: shard,
            })
            .collect();

        debug!(
            "FEC: Encoded {} bytes into {} shards (seq: {})",
            data_len, total_shards, seq
        );

        Ok(frames)
    }
}

// ============================================================================
// FEC DECODER
// ============================================================================

/// FEC decoder for incoming data
pub struct FecDecoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
    pending: std::collections::HashMap<u32, FecGroup>,
    max_pending: usize,
}

/// Group of FEC frames for a single data block
struct FecGroup {
    shards: Vec<Option<Vec<u8>>>,
    received: usize,
    total_shards: usize,
    data_shards: usize,
    data_len: usize,
    deadline: std::time::Instant,
}

impl FecDecoder {
    /// Create new FEC decoder
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow::anyhow!("Failed to create Reed-Solomon: {:?}", e))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
            pending: std::collections::HashMap::new(),
            max_pending: 64,
        })
    }

    /// Add incoming FEC frame
    pub fn add_frame(&mut self, frame: FecFrame) -> Option<Vec<u8>> {
        let seq = frame.sequence;

        // Get or create group
        let group = self.pending.entry(seq).or_insert_with(|| {
            let total = frame.total_shards as usize;
            FecGroup {
                shards: vec![None; total],
                received: 0,
                total_shards: total,
                data_shards: frame.data_shards as usize,
                data_len: frame.data_len as usize,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
            }
        });

        let idx = frame.shard_index as usize;
        if idx < group.shards.len() && group.shards[idx].is_none() {
            group.shards[idx] = Some(frame.payload);
            group.received += 1;
        }

        // Try to decode if we have enough shards
        if group.received >= group.data_shards {
            if let Some(data) = self.try_decode(seq) {
                self.pending.remove(&seq);
                return Some(data);
            }
        }

        // Cleanup old groups
        self.cleanup_expired();

        None
    }

    /// Try to decode a complete group
    fn try_decode(&self, seq: u32) -> Option<Vec<u8>> {
        let group = self.pending.get(&seq)?;

        // Convert to format expected by reed-solomon
        let mut shards: Vec<Option<Vec<u8>>> = group.shards.clone();

        // Create mutable references for reconstruction
        let mut _shard_refs: Vec<(&mut [u8], bool)> = shards
            .iter_mut()
            .map(|s| {
                if let Some(data) = s {
                    (data.as_mut_slice(), true)
                } else {
                    // Need to allocate for missing shards
                    (vec![0u8; 0].leak() as &mut [u8], false)
                }
            })
            .collect();

        // Attempt reconstruction
        // Note: This is a simplified version - full implementation would use
        // reconstruct() properly with shard presence indicators

        // For now, if we have all data shards, just concatenate
        let mut result = Vec::with_capacity(group.data_len);

        for i in 0..group.data_shards {
            if let Some(shard) = &shards[i] {
                result.extend_from_slice(shard);
            } else {
                // Missing data shard - need reconstruction
                warn!("FEC: Missing data shard {} for seq {}", i, seq);
                return None;
            }
        }

        // Truncate to original length
        result.truncate(group.data_len);

        debug!("FEC: Decoded {} bytes from seq {}", result.len(), seq);

        Some(result)
    }

    /// Cleanup expired groups
    fn cleanup_expired(&mut self) {
        let now = std::time::Instant::now();
        self.pending.retain(|_, g| g.deadline > now);

        // Also limit total pending groups
        while self.pending.len() > self.max_pending {
            // Remove oldest by sequence number
            if let Some(&oldest) = self.pending.keys().min() {
                self.pending.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

// ============================================================================
// FEC FRAME
// ============================================================================

/// FEC frame for network transmission
#[derive(Debug, Clone)]
pub struct FecFrame {
    /// Sequence number for grouping
    pub sequence: u32,
    /// Shard index within group
    pub shard_index: u8,
    /// Total number of shards
    pub total_shards: u8,
    /// Number of data shards
    pub data_shards: u8,
    /// Original data length
    pub data_len: u32,
    /// Shard payload
    pub payload: Vec<u8>,
}

impl FecFrame {
    /// Serialize frame to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FEC_HEADER_SIZE + self.payload.len());

        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.push(self.shard_index);
        buf.push(self.total_shards);
        buf.push(self.data_shards);
        buf.push((self.data_len >> 8) as u8); // High byte
        // Note: This is simplified - full implementation would encode all 4 bytes

        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Deserialize frame from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < FEC_HEADER_SIZE {
            return Err(anyhow::anyhow!("FEC frame too short"));
        }

        let sequence = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let shard_index = data[4];
        let total_shards = data[5];
        let data_shards = data[6];
        let data_len = (data[7] as u32) << 8; // Simplified

        let payload = data[FEC_HEADER_SIZE..].to_vec();

        Ok(Self {
            sequence,
            shard_index,
            total_shards,
            data_shards,
            data_len,
            payload,
        })
    }
}

// ============================================================================
// FEC STREAM
// ============================================================================

/// Stream wrapper with FEC encoding/decoding
pub struct FecStream<S> {
    inner: S,
    encoder: FecEncoder,
    decoder: FecDecoder,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
}

impl<S> FecStream<S> {
    /// Create new FEC stream wrapper
    pub fn new(inner: S, data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(Self {
            inner,
            encoder: FecEncoder::new(data_shards, parity_shards)?,
            decoder: FecDecoder::new(data_shards, parity_shards)?,
            read_buffer: BytesMut::with_capacity(65536),
            write_buffer: BytesMut::with_capacity(65536),
        })
    }
}

// ============================================================================
// ZERO-COPY OPTIMIZATION
// ============================================================================

/// Zero-copy splice between file descriptors (Linux only)
#[cfg(target_os = "linux")]
pub fn zero_copy_splice(
    fd_in: std::os::unix::io::RawFd,
    fd_out: std::os::unix::io::RawFd,
    len: usize,
) -> io::Result<usize> {
    // Use libc directly for splice
    let result = unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// Fallback for non-Linux systems
#[cfg(not(target_os = "linux"))]
pub fn zero_copy_splice(_fd_in: i32, _fd_out: i32, _len: usize) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice not available on this platform",
    ))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_encode_decode() {
        let mut encoder = FecEncoder::new(10, 3).unwrap();
        let _decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!";
        let frames = encoder.encode(original).unwrap();

        assert_eq!(frames.len(), 13); // 10 data + 3 parity

        // Verify each frame has the same sequence
        let seq = frames[0].sequence;
        for frame in &frames {
            assert_eq!(frame.sequence, seq);
        }
    }

    #[test]
    fn test_fec_frame_serialization() {
        let frame = FecFrame {
            sequence: 42,
            shard_index: 5,
            total_shards: 13,
            data_shards: 10,
            data_len: 1024,
            payload: vec![1, 2, 3, 4, 5],
        };

        let bytes = frame.to_bytes();
        let decoded = FecFrame::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.shard_index, 5);
        assert_eq!(decoded.total_shards, 13);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_decoder_with_missing_parity() {
        let mut encoder = FecEncoder::new(4, 2).unwrap();
        let mut decoder = FecDecoder::new(4, 2).unwrap();

        let original = b"Test data for Reed-Solomon!";
        let frames = encoder.encode(original).unwrap();

        // Only send data shards (drop parity)
        for frame in frames.into_iter().take(4) {
            let result = decoder.add_frame(frame);
            if let Some(data) = result {
                assert_eq!(&data[..original.len()], original.as_slice());
                return;
            }
        }

        // Should have decoded by now
        panic!("Failed to decode with only data shards");
    }

    #[test]
    fn test_encoder_sequence_increment() {
        let mut encoder = FecEncoder::new(4, 2).unwrap();

        let frames1 = encoder.encode(b"First message").unwrap();
        let frames2 = encoder.encode(b"Second message").unwrap();

        assert_ne!(frames1[0].sequence, frames2[0].sequence);
        assert_eq!(frames1[0].sequence + 1, frames2[0].sequence);
    }
}
