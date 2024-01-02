//! Linux Cooked Link Layer version 2

use std::convert::TryInto as _;

use serde::Serialize;

use crate::errors::Error;
use crate::{Layer, Packet, ENCAP_TYPE_LINUX_SLL2};

use crate::layers::ethernet::ETHERTYPES_MAP;

#[derive(Debug, Default, Serialize)]
pub struct LinuxSll2 {
    proto_type: u16,
    reserved: u16,
    iface_idx: u32,
    ll_type: u16,
    packet_type: u8,
    ll_addr_len: u8,
    ll_addr: [u8; 8],
}

// Register our Encap Types with the Packet.
pub(crate) fn register_defaults() -> Result<(), Error> {
    Packet::register_encap_type(ENCAP_TYPE_LINUX_SLL2, LinuxSll2::creator)
}

const LINUX_SLL2_HEADER_LEN: usize = 20_usize;

impl LinuxSll2 {
    pub(crate) fn creator() -> Box<dyn Layer + Send> {
        Box::<LinuxSll2>::default()
    }
}

impl Layer for LinuxSll2 {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < LINUX_SLL2_HEADER_LEN {
            return Err(Error::TooShort {
                required: LINUX_SLL2_HEADER_LEN,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }
        self.proto_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        self.reserved = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        self.iface_idx = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        self.ll_type = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        self.packet_type = bytes[10];
        self.ll_addr_len = bytes[11];
        self.ll_addr = bytes[12..20].try_into().unwrap();

        let map = ETHERTYPES_MAP.read().unwrap();
        let layer = map.get(&self.proto_type);
        match layer {
            None => Ok((None, LINUX_SLL2_HEADER_LEN)),
            Some(l3_creator) => Ok((Some(l3_creator()), LINUX_SLL2_HEADER_LEN)),
        }
    }

    fn name(&self) -> &'static str {
        "Linux SLL Version 2"
    }

    fn short_name(&self) -> &'static str {
        "linux_sll2"
    }
}
