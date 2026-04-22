// src/fec/rs.rs
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io::{self, Error, ErrorKind};
use bytes::{Bytes, BytesMut, BufMut};

/// FEC Packet Header:
/// [Group ID: 2 bytes] [Shard ID: 1 byte] [Total Shards: 1 byte]
pub const FEC_HEADER_SIZE: usize = 4;

#[derive(Debug, Clone)]
pub struct FecPacket {
    pub group_id: u16,
    pub shard_id: u8,
    pub total_shards: u8,
    pub data: Bytes,
}

impl FecPacket {
    pub fn encode_header(&self, dest: &mut BytesMut) {
        dest.put_u16(self.group_id);
        dest.put_u8(self.shard_id);
        dest.put_u8(self.total_shards);
        dest.extend_from_slice(&self.data);
    }

    pub fn decode(src: &[u8]) -> io::Result<Self> {
        if src.len() < FEC_HEADER_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "Packet too small for FEC header"));
        }

        let group_id = u16::from_be_bytes([src[0], src[1]]);
        let shard_id = src[2];
        let total_shards = src[3];
        let data = Bytes::copy_from_slice(&src[FEC_HEADER_SIZE..]);

        Ok(Self {
            group_id,
            shard_id,
            total_shards,
            data,
        })
    }
}

pub struct FecEncoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
    next_group_id: u16,
}

impl FecEncoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> io::Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| Error::other(e.to_string()))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
            next_group_id: rand::random(),
        })
    }

    pub fn encode(&mut self, data: &[Bytes]) -> io::Result<Vec<FecPacket>> {
        if data.len() != self.data_shards {
            return Err(Error::new(ErrorKind::InvalidInput, "Incorrect number of data shards"));
        }

        // Ensure all shards are same length - use the maximum length and pad others
        let max_len = data.iter().map(|b| b.len()).max().unwrap_or(0);
        let mut shards: Vec<Vec<u8>> = data.iter()
            .map(|b| {
                let mut v = b.to_vec();
                v.resize(max_len, 0);
                v
            })
            .collect();

        // Add parity buffers
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; max_len]);
        }

        self.rs.encode(&mut shards)
            .map_err(|e| Error::other(e.to_string()))?;

        let group_id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);

        let total_shards = (self.data_shards + self.parity_shards) as u8;
        let packets = shards.into_iter().enumerate()
            .map(|(i, s)| FecPacket {
                group_id,
                shard_id: i as u8,
                total_shards,
                data: Bytes::from(s),
            })
            .collect();

        Ok(packets)
    }
}

pub struct FecDecoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl FecDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> io::Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| Error::other(e.to_string()))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
        })
    }

    pub fn decode(&self, mut shards: Vec<Option<Vec<u8>>>) -> io::Result<Vec<Vec<u8>>> {
        let total_shards = self.data_shards + self.parity_shards;
        if shards.len() != total_shards {
            return Err(Error::new(ErrorKind::InvalidInput, "Incorrect number of shards for decoder"));
        }

        // Perform reconstruction
        self.rs.reconstruct(&mut shards)
            .map_err(|e| Error::other(e.to_string()))?;

        // Extract only data shards
        let data = shards.into_iter()
            .take(self.data_shards)
            .map(|opt| opt.expect("Reconstruction guaranteed this exists"))
            .collect();

        Ok(data)
    }
}
