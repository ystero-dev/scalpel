//! SCTP Layer for `scalpel`
use core::convert::TryInto;

use std::collections::HashMap;

use lazy_static::lazy_static;
use serde::{ser::SerializeStruct, Serialize, Serializer};

use crate::errors::Error;
use crate::layer::Layer;

use crate::layers::{ipv4, ipv6};

lazy_static! {
    // FIXME : Ugly hack because `serde serialize_field does not accept anything other than static
    static ref CHUNK_DISPLAY_MAP: HashMap<usize, &'static str> = {
        let mut m = HashMap::new();
        m.insert(0, "# 1");
        m.insert(1, "# 2");
        m.insert(2, "# 3");
        m.insert(3, "# 4");
        m.insert(4, "# 5");
        m.insert(5, "# 6");
        m.insert(6, "# 7");
        m.insert(7, "# 8");
        m
    };
    static ref HIGHER_CHUNK: &'static str = "# ##";
}
/// SCTP Protocol Number
pub const IPPROTO_SCTP: u8 = 132_u8;

// Register ourselves With IPv4 and IPv6
pub(crate) fn register_defaults() -> Result<(), Error> {
    ipv4::register_protocol(IPPROTO_SCTP, SCTP::creator)?;
    ipv6::register_next_header(IPPROTO_SCTP, SCTP::creator)?;

    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
enum ChunkPayload {
    UnProcessed(Vec<u8>),

    #[serde(serialize_with = "serialize_sctp_chunk_layer")]
    Processed(Box<dyn Layer>),
}

fn serialize_sctp_chunk_layer<S>(
    chunk_layer: &Box<dyn Layer>,
    serializer: S,
) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct(chunk_layer.short_name(), 1)?;
    state.serialize_field(chunk_layer.short_name(), chunk_layer)?;
    state.end()
}

impl Default for ChunkPayload {
    fn default() -> Self {
        Self::UnProcessed(vec![])
    }
}

#[derive(Debug, Default, Serialize)]
struct SCTPChunk {
    chunk_type: u8,
    chunk_flags: u8,
    chunk_len: u16,
    payload: ChunkPayload,
}

fn serialize_sctp_chunks<S>(
    chunks: &Vec<SCTPChunk>,
    serializer: S,
) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("chunks", chunks.len())?;
    for (idx, chunk) in chunks.iter().enumerate() {
        state.serialize_field(CHUNK_DISPLAY_MAP.get(&idx).unwrap_or(&HIGHER_CHUNK), chunk)?;
    }
    state.end()
}

#[derive(Debug, Default, Serialize)]
struct SCTP {
    src_port: u16,
    dst_port: u16,
    verification_tag: u32,
    checksum: u32,

    #[serde(serialize_with = "serialize_sctp_chunks")]
    chunks: Vec<SCTPChunk>,
}

impl SCTP {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(SCTP::default())
    }
}

impl Layer for SCTP {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        self.src_port = (bytes[0] as u16) << 8 | (bytes[1] as u16);
        self.dst_port = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.verification_tag = u32::from_be_bytes(bytes[4..8].try_into().unwrap())
            .try_into()
            .unwrap();
        self.checksum = u32::from_be_bytes(bytes[8..12].try_into().unwrap())
            .try_into()
            .unwrap();

        let mut chunks = vec![];
        let mut start = 12;
        loop {
            let chunk_type = bytes[start];
            start += 1;
            let chunk_flags = bytes[start];
            start += 1;
            let chunk_len = (bytes[start] as u16) << 8 | (bytes[start + 1] as u16);
            start += 2;
            let payload: Vec<u8> = bytes[start + 2..start + chunk_len as usize - 4].into();
            start += chunk_len as usize - 4;

            chunks.push(SCTPChunk {
                chunk_type,
                chunk_flags,
                chunk_len,
                payload: ChunkPayload::UnProcessed(payload),
            });
            if start >= bytes.len() {
                break;
            }
        }
        self.chunks = chunks;
        Ok((None, bytes.len()))
    }

    fn name(&self) -> &'static str {
        "SCTP"
    }

    fn short_name(&self) -> &'static str {
        "sctp"
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::layers;
    use crate::packet::Packet;
    use crate::types::ENCAP_TYPE_ETH;

    #[test]
    fn test_basic_sctp_decode() {
        let _ = layers::register_defaults();
        let array = hex::decode(
"00005096523a0026cb39f4c00800450000a8da490000fa844bf6585206860aad300d189f0b5add68d33d0f7373ab030000100629beaa0000fa000000000000030028d42b4897000000050000000301000202000000180012000800000a43000600080000045600030028d42b4898000000060000000301000202000000180012000800000a42000600080000045600030028d42b4899000000070000000301000202000000180012000800000fa20006000800000456");
        assert!(array.is_ok());

        let array = array.unwrap();
        let len = array.len();
        let p = Packet::from_u8(&array, ENCAP_TYPE_ETH);
        assert!(p.is_ok(), "{:?}", p.err());

        let p = p.unwrap();
        assert!(p.layers.len() == 3, "{:#?}", p);
    }
}
