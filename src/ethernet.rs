//! Ethernet Layer

use crate::types::MACAddress;
use crate::Error;
use crate::Layer;

const ETH_HEADER_LEN: usize = 14_usize;

pub type EtherType = u16;

#[derive(Debug, Default, Clone)]
pub struct Ethernet {
    src_mac: MACAddress,
    dst_mac: MACAddress,
    ethertype: EtherType,
}

impl Layer for Ethernet {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        if bytes.len() < ETH_HEADER_LEN {
            return Err(Error::TooShort);
        }
        self.src_mac = bytes[0..6].into();
        self.dst_mac = bytes[6..12].into();
        self.ethertype = (bytes[12] as u16) << 8 | bytes[13] as u16;
        Ok((None, 14))
    }
}
