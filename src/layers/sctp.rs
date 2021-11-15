//! SCTP Layer for `scalpel`
use core::convert::TryInto;

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::{ser::SerializeStruct as _, Serialize, Serializer};

use crate::errors::Error;
use crate::layer::Layer;
use crate::types::LayerCreatorFn;

use crate::layers::{ipv4, ipv6};

lazy_static! {
    // A Map of Chunk Type to Display String
    static ref CHUNK_DISPLAY_MAP: HashMap<u8, &'static str> = {
        let mut m = HashMap::new();
        m.insert(0, "DATA Chunk");
        m.insert(1, "INIT Chunk");
        m.insert(2, "INIT-ACK Chunk");
        m.insert(3, "SACK Chunk");
        m.insert(4, "HEARTBEAT Chunk");
        m.insert(5, "HEARTBEAT-ACK Chunk");
        m.insert(6, "ABORT Chunk");
        m.insert(7, "SHUTDOWN Chunk");
        m.insert(8, "SHUTDOWN-ACK Chunk");
        m.insert(9, "ERROR Chunk");
        m.insert(10, "COOKIE-ECHO Chunk");
        m.insert(11, "COOKIE-ACK Chunk");
        m.insert(12, "ECNE Chunk");
        m.insert(13, "CWR Chunk");
        m.insert(14, "SHUTDOWN_COMPLETE Chunk");
        m.insert(15, "AUTH Chunk");
        m.insert(64, "I-DATA Chunk");
        m.insert(128, "ASCONF-ACK Chunk");
        m.insert(130, "RE-CONFIG Chunk");
        m.insert(132, "PAD Chunk");
        m.insert(192, "FORWARD-TSN Chunk");
        m.insert(193, "ASCONF Chunk");
        m.insert(195, "I-FORWARD-TSN Chunk");
        m
    };
    static ref UNKNOWN_CHUNK_TYPE: &'static str = "Unknown Chunk";

    static ref PROTOCOLS_MAP: RwLock<HashMap<u32, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

/// SCTP Protocol Number
pub const IPPROTO_SCTP: u8 = 132_u8;

/// For Registering Data Chunk Protocols with Us.
///
/// This will be used by M3UA (say)
pub fn register_datachunk_protocol(proto: u32, creator: LayerCreatorFn) -> Result<(), Error> {
    let mut map = PROTOCOLS_MAP.write().unwrap();
    if map.contains_key(&proto) {
        return Err(Error::RegisterError);
    }
    map.insert(proto, creator);

    Ok(())
}

// Register ourselves With IPv4 and IPv6
pub(crate) fn register_defaults() -> Result<(), Error> {
    ipv4::register_protocol(IPPROTO_SCTP, SCTP::creator)?;
    ipv6::register_next_header(IPPROTO_SCTP, SCTP::creator)?;

    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
enum ChunkPayload {
    #[serde(serialize_with = "hex::serde::serialize")]
    UnProcessed(Vec<u8>),

    #[serde(serialize_with = "serialize_sctp_chunk_layer")]
    Processed(Box<dyn Layer + Send>),
}

fn serialize_sctp_chunk_layer<S>(
    chunk_layer: &Box<dyn Layer + Send>,
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
struct SCTPChunkHeader {
    chunk_type: u8,
    chunk_flags: u8,
    chunk_len: u16,
}

#[derive(Debug, Serialize)]
enum SCTPChunk {
    Data {
        header: SCTPChunkHeader,
        tsn: u32,
        stream_id: u16,
        stream_seq_no: u16,
        payload_proto: u32,
        payload: ChunkPayload,
    },
    Unsupported {
        header: SCTPChunkHeader,
        payload: ChunkPayload,
    },
}

impl SCTPChunk {
    #[inline(always)]
    fn chunk_type(&self) -> u8 {
        match self {
            Self::Data { ref header, .. } | Self::Unsupported { ref header, .. } => {
                header.chunk_type
            }
        }
    }
}

impl Default for SCTPChunk {
    fn default() -> Self {
        Self::Unsupported {
            header: SCTPChunkHeader::default(),
            payload: ChunkPayload::default(),
        }
    }
}

fn serialize_sctp_chunks<S>(
    chunks: &Vec<SCTPChunk>,
    serializer: S,
) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("chunks", chunks.len())?;
    for chunk in chunks {
        state.serialize_field(
            CHUNK_DISPLAY_MAP
                .get(&chunk.chunk_type())
                .unwrap_or(&UNKNOWN_CHUNK_TYPE),
            chunk,
        )?;
    }
    state.end()
}

#[derive(Debug, Default, Serialize)]
pub struct SCTP {
    src_port: u16,
    dst_port: u16,
    verification_tag: u32,
    checksum: u32,

    #[serde(serialize_with = "serialize_sctp_chunks")]
    chunks: Vec<SCTPChunk>,
}

impl SCTP {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::new(SCTP::default())
    }

    fn process_chunk_header(bytes: &[u8]) -> Result<SCTPChunkHeader, Error> {
        if bytes.len() < 4 {
            return Err(Error::TooShort);
        }

        let chunk_type = bytes[0];
        let chunk_flags = bytes[1];
        let chunk_len = (bytes[2] as u16) | (bytes[3] as u16);

        Ok(SCTPChunkHeader {
            chunk_type,
            chunk_flags,
            chunk_len,
        })
    }

    fn process_data_chunk(bytes: &[u8]) -> Result<(SCTPChunk, usize), Error> {
        let mut start = 0;

        let header = SCTP::process_chunk_header(&bytes[start..])?;
        start += 4;

        let tsn = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
            .try_into()
            .unwrap();
        start += 4;

        let stream_id = (bytes[start] as u16) | (bytes[start + 1] as u16);
        start += 2;

        let stream_seq_no = (bytes[start] as u16) | (bytes[start + 1] as u16);
        start += 2;

        let payload_proto = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
            .try_into()
            .unwrap();
        start += 4;

        let map = PROTOCOLS_MAP.read().unwrap();
        let layer_creator = map.get(&payload_proto);
        let payload = if layer_creator.is_none() {
            let payload: Vec<u8> = bytes[start..start + header.chunk_len as usize - 16].into();

            ChunkPayload::UnProcessed(payload)
        } else {
            let layer_creator = layer_creator.unwrap();
            let mut layer = layer_creator();
            let (_, _processed) = layer.from_bytes(&bytes[start..])?;

            ChunkPayload::Processed(layer)
        };

        let chunk_len = header.chunk_len as usize;
        Ok((
            SCTPChunk::Data {
                header,
                tsn,
                stream_id,
                stream_seq_no,
                payload_proto,
                payload,
            },
            chunk_len,
        ))
    }

    fn process_unsupported_chunk(bytes: &[u8]) -> Result<(SCTPChunk, usize), Error> {
        let mut start = 0;

        let header = SCTP::process_chunk_header(&bytes[start..])?;
        start += 4;

        let payload: Vec<u8> = bytes[start..start + header.chunk_len as usize - 4].into();
        let payload = ChunkPayload::UnProcessed(payload);

        let chunk_len = header.chunk_len as usize;
        Ok((SCTPChunk::Unsupported { header, payload }, chunk_len))
    }

    fn process_sctp_chunk(bytes: &[u8]) -> Result<(SCTPChunk, usize), Error> {
        let chunk_type = bytes[0];

        match chunk_type {
            0 => SCTP::process_data_chunk(bytes),
            _ => SCTP::process_unsupported_chunk(bytes),
        }
    }
}

impl Layer for SCTP {
    fn from_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
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
            let (chunk, chunk_consumed) = SCTP::process_sctp_chunk(&bytes[start..])?;
            start += chunk_consumed;

            chunks.push(chunk);
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
        let p = Packet::from_bytes(&array, ENCAP_TYPE_ETH);
        assert!(p.is_ok(), "{:?}", p.err());

        let p = p.unwrap();
        assert!(p.layers.len() == 3, "{:#?}", p);
    }
}
