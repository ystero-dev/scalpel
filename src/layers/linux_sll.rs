//! Linux Cooked Link Layer version 1

use std::convert::TryInto as _;

use serde::Serialize;

use crate::errors::Error;
use crate::{Layer, Packet, ENCAP_TYPE_LINUX_SLL};

use crate::layers::ethernet::ETHERTYPES_MAP;

#[derive(Debug, Default, Serialize)]
pub struct LinuxSll {
    packet_type: u16,
    ll_type: u16,
    ll_addr_len: u16,
    ll_addr: [u8; 8],
    protocol: u16,
}

// Register our Encap Types with the Packet.
pub(crate) fn register_defaults() -> Result<(), Error> {
    Packet::register_encap_type(ENCAP_TYPE_LINUX_SLL, LinuxSll::creator)
}

const LINUX_SLL_HEADER_LEN: usize = 16_usize;

impl LinuxSll {
    pub(crate) fn creator() -> Box<dyn Layer + Send> {
        Box::<LinuxSll>::default()
    }
}

impl Layer for LinuxSll {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < LINUX_SLL_HEADER_LEN {
            return Err(Error::TooShort);
        }
        self.packet_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        self.ll_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        self.ll_addr_len = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        self.ll_addr = bytes[6..14].try_into().unwrap();
        self.protocol = u16::from_be_bytes(bytes[14..16].try_into().unwrap());

        let map = ETHERTYPES_MAP.read().unwrap();
        let layer = map.get(&self.protocol);
        match layer {
            None => Ok((None, LINUX_SLL_HEADER_LEN)),
            Some(l3_creator) => Ok((Some(l3_creator()), LINUX_SLL_HEADER_LEN)),
        }
    }

    fn name(&self) -> &'static str {
        "Linux SLL Version 1"
    }

    fn short_name(&self) -> &'static str {
        "linux_sll"
    }
}
