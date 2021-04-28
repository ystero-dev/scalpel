//! IPv4 Layer

use std::convert::TryInto;

use crate::errors::Error;
use crate::layer::Layer;

#[derive(Debug, Default, Clone)]
pub struct IPv4 {
    version: u8,
    hdr_len: u8,
    tos: u8,
    len: u16,
    id: u16,
    flags: u8,
    frag_offset: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
    // FIXME: Add options
}

impl IPv4 {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(IPv4::default())
    }
}

impl Layer for IPv4 {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        self.version = bytes[0] >> 4;
        self.hdr_len = bytes[0] & 0x0f;
        if bytes.len() < self.hdr_len.into() {
            return Err(Error::ParseError);
        }
        self.tos = bytes[1];
        self.len = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        self.id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let flags_offset = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        self.flags = (flags_offset >> 13) as u8;
        self.frag_offset = flags_offset & 0xe0;
        self.ttl = bytes[8];
        self.proto = bytes[9];
        self.checksum = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
        self.src_addr = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        self.dst_addr = u32::from_be_bytes(bytes[16..20].try_into().unwrap());

        Ok((None, 20))
    }

    fn name(&self) -> &str {
        "IPv4"
    }

    fn short_name(&self) -> &str {
        "ip"
    }
}
