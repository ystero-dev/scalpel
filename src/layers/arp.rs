//! Address Resolution Protocol (ARP) Handling

use core::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layer::Layer;
use crate::layers::ethernet;
use crate::types::{IPv4Address, MACAddress, ETHERTYPE_ARP};

/// Default Header Length for IPv4 Packets
pub const ARP_HDR_LENGTH: usize = 28_usize;

// Register outselves with Ethernet layer
pub(crate) fn register_defaults() -> Result<(), Error> {
    ethernet::register_ethertype(ETHERTYPE_ARP, ARP::creator)
}

#[derive(Debug, Default, Serialize)]
pub struct ARP {
    #[serde(serialize_with = "crate::types::hex::serialize_upper_hex_u16")]
    htype: u16,
    #[serde(serialize_with = "crate::types::hex::serialize_upper_hex_u16")]
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sender_ha: MACAddress,
    target_ha: MACAddress,
    sender_pa: IPv4Address,
    target_pa: IPv4Address,
}

impl ARP {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::new(ARP::default())
    }
}

impl Layer for ARP {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < ARP_HDR_LENGTH {
            return Err(Error::ParseError);
        }

        self.htype = (bytes[0] as u16) << 8 | (bytes[1] as u16);
        self.ptype = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.hlen = bytes[4];
        self.plen = bytes[5];
        self.oper = (bytes[6] as u16) << 8 | (bytes[7] as u16);
        self.sender_ha = bytes[8..14].try_into()?;
        self.sender_pa = bytes[14..18].try_into()?;
        self.target_ha = bytes[18..24].try_into()?;
        self.target_pa = bytes[24..28].try_into()?;

        Ok((None, ARP_HDR_LENGTH))
    }

    fn name(&self) -> &'static str {
        "ARP"
    }

    fn short_name(&self) -> &'static str {
        "arp"
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn parse_arp_simple() {
        use crate::layers;
        use crate::packet::Packet;
        use crate::types::ENCAP_TYPE_ETH;

        let _ = layers::register_defaults();

        let array = hex::decode("c402326b0000c4013258000008060001080006040001c401325800000a000001c402326b00000a000002000000000000000000000000000000000000");
        assert!(array.is_ok());
        let array = array.unwrap();

        let p = Packet::from_bytes(&array, ENCAP_TYPE_ETH);
        assert!(p.is_ok(), "{:?}", p.err());

        let p = p.unwrap();
        assert!(p.layers.len() == 2, "{:?}", p);
    }
}
