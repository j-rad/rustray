// src/fec/transport.rs
use lru::LruCache;
use std::num::NonZeroUsize;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use bytes::{BytesMut, Bytes};
use crate::fec::rs::{FecPacket, FecEncoder, FecDecoder, FEC_HEADER_SIZE};

/// FEC Configuration
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
pub struct FecConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 3, // 30% loss tolerance approx
        }
    }
}

pub struct FecUdpSocket {
    socket: UdpSocket,
    config: FecConfig,
    encoder: Mutex<FecEncoder>,
    // Group reassembly: GroupId -> (ReceivedCount, Shards)
    groups: Mutex<LruCache<u16, (usize, Vec<Option<Vec<u8>>>)>>,
}

impl FecUdpSocket {
    pub fn new(socket: UdpSocket, config: FecConfig) -> io::Result<Self> {
        let encoder = FecEncoder::new(config.data_shards, config.parity_shards)?;
        
        Ok(Self {
            socket,
            config,
            encoder: Mutex::new(encoder),
            groups: Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())),
        })
    }

    /// Send a block of data using FEC
    pub async fn send_fec(&self, data: &[Bytes], target: SocketAddr) -> io::Result<()> {
        let mut encoder = self.encoder.lock().await;
        let packets = encoder.encode(data)?;
        
        for packet in packets {
            let mut buf = BytesMut::with_capacity(FEC_HEADER_SIZE + packet.data.len());
            packet.encode_header(&mut buf);
            self.socket.send_to(&buf, target).await?;
        }
        
        Ok(())
    }

    /// Receive a packet and attempt reassembly
    /// Returns a list of reconstructed data shards if a group is completed.
    pub async fn recv_fec(&self) -> io::Result<(Vec<Bytes>, SocketAddr)> {
        let mut buf = [0u8; 2048];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            let packet = FecPacket::decode(&buf[..len])?;
            
            let mut groups = self.groups.lock().await;
            let group_id = packet.group_id;
            let total_shards = packet.total_shards as usize;
            
            if !groups.contains(&group_id) {
                groups.put(group_id, (0, vec![None; total_shards]));
            }
            let entry = groups.get_mut(&group_id).unwrap();
            
            if entry.1[packet.shard_id as usize].is_none() {
                entry.1[packet.shard_id as usize] = Some(packet.data.to_vec());
                entry.0 += 1;
            }
            
            // If we have enough shards to decode
            if entry.0 >= self.config.data_shards {
                let decoder = FecDecoder::new(self.config.data_shards, self.config.parity_shards)?;
                
                // We use entry.1.clone() before removing
                let shards_to_decode = entry.1.clone();
                let reconstructed = decoder.decode(shards_to_decode)?;
                
                // Remove group once decoded
                groups.pop(&group_id);
                
                let result = reconstructed.into_iter().map(Bytes::from).collect();
                return Ok((result, src));
            }
        }
    }
}
