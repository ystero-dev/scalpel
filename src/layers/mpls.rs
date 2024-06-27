//! Multi Label Protocol Switching

use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layers::ethernet;
use crate::types::{ETHERTYPE_MPLS_MULTICAST, ETHERTYPE_MPLS_UNICAST};
use crate::Layer;

use super::ipv4::IPv4;

/// Default Header Length for MPLS Packets
pub const MPLS_HEADER_LENGTH: usize = 4_usize;

// Register Ourselves to the Ethernet layer, as this is a 2.5 layer protocol
pub(crate) fn register_defaults() -> Result<(), Error> {
    ethernet::register_ethertype(ETHERTYPE_MPLS_UNICAST, MPLS::creator)?;
    ethernet::register_ethertype(ETHERTYPE_MPLS_MULTICAST, MPLS::creator)
}

#[derive(Debug, Default, Serialize, Copy, Clone)]
pub struct MPLSLabel {
    //Make built-in types
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u32")]
    label: u32, //This is only 20 bits
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    exp: u8, //This is only 3 bits
    // #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    bos: bool, //This is only 1 bit
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    ttl: u8, //This is 1 byte
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct MPLS {
    labels: Vec<MPLSLabel>,
}

impl MPLS {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::<MPLS>::default()
    }
}

impl Layer for MPLS {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < MPLS_HEADER_LENGTH {
            return Err(Error::TooShort {
                required: MPLS_HEADER_LENGTH,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }

        let mut byte_offset = 0;

        loop {
            //FIXME:For now the first few bits are not useful in label,exp and bos
            let label =
                u32::from_be_bytes(bytes[byte_offset..(byte_offset + 4)].try_into().unwrap()) >> 12;
            let exp = u8::from_be(bytes[byte_offset + 2] << 4) >> 5;
            let bos = bytes[byte_offset + 2] & 0x01 == 0x01;
            let ttl = bytes[byte_offset + 3];

            self.labels.push(MPLSLabel {
                label,
                exp,
                bos,
                ttl,
            });
            byte_offset += MPLS_HEADER_LENGTH;

            if bos {
                break;
            }
        }

        //FIXME:Support IPV6
        Ok((Some(IPv4::creator()), byte_offset))
    }

    fn name(&self) -> &'static str {
        "MPLS"
    }

    fn short_name(&self) -> &'static str {
        "mpls"
    }
}

#[cfg(test)]
mod tests {

    use crate::layers;
    use crate::{Layer, Packet, ENCAP_TYPE_ETH};

    wasm_tests! {
        #[test]
        fn parse_valid_mpls_packet() {
            let _ = layers::register_defaults();

            let mpls_packet = vec![
                0x00, 0x30, 0x96, 0xe6, 0xfc, 0x39, 0x00, 0x30, 0x96, 0x05, 0x28, 0x38, 0x88, 0x47,
                0x00, 0x01, 0xdd, 0xff, 0x45, 0xc0, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0xff, 0x06,
                0xa4, 0xe8, 0x0a, 0x01, 0x02, 0x01, 0x0a, 0x22, 0x00, 0x01, 0x2a, 0xf9, 0x00, 0x17,
                0x98, 0x32, 0x10, 0x05, 0x8d, 0xd5, 0x8e, 0xa5, 0x50, 0x10, 0x10, 0x20, 0x99, 0xcd,
                0x00, 0x00, 0x00, 0x00,
            ];

            let mut mpls: Box<dyn Layer> = Box::new(super::MPLS::default());

            let p = mpls.decode_bytes(&mpls_packet[28..]);
            assert!(p.is_ok(), "{:#?}", mpls);
        }

        #[test]
        fn test_mpls_parse_regression() {
            let _ = layers::register_defaults();

            // testPacketMPLS is the packet:
            //     Ethernet II, Src: Cisco_05:28:38 (00:30:96:05:28:38), Dst: Cisco_e6:fc:39 (00:30:96:e6:fc:39)
            //     0x0000   00 30 96 e6 fc 39 00 30 96 05 28 38 88 47 00 01   .0...9.0..(8.G..
            //     0x0010   dd ff 45 c0 00 28 00 03 00 00 ff 06 a4 e8 0a 01   ..E..(..........
            //     0x0020   02 01 0a 22 00 01 2a f9 00 17 98 32 10 05 8d d5   ..."..*....2....
            //     0x0030   8e a5 50 10 10 20 99 cd 00 00 00 00               ..P.. ......

            let test_packet_mpls = vec![
                0x00, 0x30, 0x96, 0xe6, 0xfc, 0x39, 0x00, 0x30, 0x96, 0x05, 0x28, 0x38, 0x88, 0x47,
                0x00, 0x01, 0xdd, 0xff, 0x45, 0xc0, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0xff, 0x06,
                0xa4, 0xe8, 0x0a, 0x01, 0x02, 0x01, 0x0a, 0x22, 0x00, 0x01, 0x2a, 0xf9, 0x00, 0x17,
                0x98, 0x32, 0x10, 0x05, 0x8d, 0xd5, 0x8e, 0xa5, 0x50, 0x10, 0x10, 0x20, 0x99, 0xcd,
                0x00, 0x00, 0x00, 0x00,
            ];

            let p = Packet::from_bytes(&test_packet_mpls, ENCAP_TYPE_ETH);
            assert!(p.is_ok());
            let p = p.unwrap();
            assert!(p.layers.len() == 4, "{:#?}", p);
        }
    }
}
