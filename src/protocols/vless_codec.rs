use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use uuid::Uuid;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct VlessRequest {
    pub version: u8,
    pub uuid: [u8; 16],
    pub addons: Vec<u8>,
    pub command: u8, // 1 TCP, 2 UDP
    pub port: u16,
    pub address_type: u8,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct VlessResponse {
    pub version: u8,
    pub addons: Vec<u8>,
}

pub struct VlessRequestDecoder;

impl Decoder for VlessRequestDecoder {
    type Item = VlessRequest;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 18 {
            return Ok(None);
        }
        let version = src[0];
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&src[1..17]);
        let addons_len = src[17] as usize;

        if src.len() < 18 + addons_len + 4 {
            return Ok(None);
        }

        let addons = src[18..18 + addons_len].to_vec();
        let cmd_offset = 18 + addons_len;
        let command = src[cmd_offset];
        let port = u16::from_be_bytes([src[cmd_offset + 1], src[cmd_offset + 2]]);
        let address_type = src[cmd_offset + 3];

        let addr_offset = cmd_offset + 4;

        let (address, total_len) = match address_type {
            1 => {
                if src.len() < addr_offset + 4 {
                    return Ok(None);
                }
                let ip = Ipv4Addr::new(src[addr_offset], src[addr_offset+1], src[addr_offset+2], src[addr_offset+3]);
                (ip.to_string(), addr_offset + 4)
            }
            2 => {
                if src.len() < addr_offset + 1 {
                    return Ok(None);
                }
                let domain_len = src[addr_offset] as usize;
                if src.len() < addr_offset + 1 + domain_len {
                    return Ok(None);
                }
                let domain = String::from_utf8(src[addr_offset + 1 .. addr_offset + 1 + domain_len].to_vec())
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid domain"))?;
                (domain, addr_offset + 1 + domain_len)
            }
            3 => {
                if src.len() < addr_offset + 16 {
                    return Ok(None);
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&src[addr_offset..addr_offset+16]);
                let ip = Ipv6Addr::from(ip_bytes);
                (ip.to_string(), addr_offset + 16)
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid address type")),
        };

        src.advance(total_len);

        Ok(Some(VlessRequest {
            version,
            uuid,
            addons,
            command,
            port,
            address_type,
            address,
        }))
    }
}

pub struct VlessResponseEncoder;

impl Encoder<VlessResponse> for VlessResponseEncoder {
    type Error = std::io::Error;

    fn encode(&mut self, item: VlessResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(item.version);
        dst.put_u8(item.addons.len() as u8);
        dst.put_slice(&item.addons);
        Ok(())
    }
}
