// src/transport/s3_codec.rs
use crate::error::Result;
use bytes::{BufMut, BytesMut};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

pub const S3_BLOB_SIZE: usize = 65536; // 64KB
const BACKUP_HEADER_MAGIC: &[u8] = b"ENT_BKP_V2_";

pub struct S3Codec {
    buffer: BytesMut,
}

impl S3Codec {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(S3_BLOB_SIZE * 2),
        }
    }

    /// Encode internal frames into disguised payload for S3 PUT
    pub fn encode_blob(&mut self, data: &[u8]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(S3_BLOB_SIZE);

        // Add fake enterprise backup header
        blob.extend_from_slice(BACKUP_HEADER_MAGIC);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        blob.extend_from_slice(&timestamp.to_le_bytes()); // 8 bytes

        let data_len = data.len() as u32;
        blob.extend_from_slice(&data_len.to_le_bytes()); // 4 bytes

        // Write actual data
        blob.extend_from_slice(data);

        // Pad to S3_BLOB_SIZE with random data
        let current_len = blob.len();
        if current_len < S3_BLOB_SIZE {
            let pad_len = S3_BLOB_SIZE - current_len;
            let mut padding = vec![0u8; pad_len];
            rand::thread_rng().fill_bytes(&mut padding);
            blob.extend_from_slice(&padding);
        }

        blob
    }

    /// Decode the S3 format back into original Flow-J data
    pub fn decode_blob(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < BACKUP_HEADER_MAGIC.len() + 12 {
            return Err(anyhow::anyhow!("Payload too short for S3 format"));
        }

        if &payload[0..BACKUP_HEADER_MAGIC.len()] != BACKUP_HEADER_MAGIC {
            return Err(anyhow::anyhow!("Invalid S3 blob magic"));
        }

        let mut offset = BACKUP_HEADER_MAGIC.len() + 8; // skip magic + timestamp

        // Read data length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&payload[offset..offset + 4]);
        let data_len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;

        if offset + data_len > payload.len() {
            return Err(anyhow::anyhow!("S3 blob data truncated"));
        }

        // Return actual data (strip padding)
        Ok(payload[offset..offset + data_len].to_vec())
    }
}
