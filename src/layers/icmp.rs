//! ICMP Datagram

use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layers::ipv4;
use crate::types::IPv4Address;
use crate::Layer;

/// IANA Assigned protocol number for ICMP
pub const IPPROTO_ICMP: u8 = 1_u8;
/// ICMP header length
pub const ICMP_HEADER_LENGTH: usize = 8_usize;

/// ICMP types
pub const ICMP_ECHO_REPLY: u8 = 0_u8;
pub const ICMP_ECHO_REQUEST: u8 = 8_u8;
pub const ICMP_DESTINATION_UNREACHABLE: u8 = 3_u8;
pub const ICMP_SOURCE_QUENCH: u8 = 4_u8;
pub const ICMP_REDIRECT: u8 = 5_u8;
pub const ICMP_TIME_EXCEEDED: u8 = 11_u8;

// Register ICMP with Protocol Handler in IPv4
pub(crate) fn register_defaults() -> Result<(), Error> {
    ipv4::register_protocol(IPPROTO_ICMP, ICMP::creator)
}

#[derive(Default, Debug, Serialize)]
#[serde(untagged)]
pub enum IcmpType {
    #[default]
    Empty,
    Unsupported(IcmpUnsupported),
    #[serde[rename = "unsupported"]]
    EchoRequest(IcmpEcho),
    EchoReply(IcmpEcho),
    Redirect(IcmpRedirect),
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpEcho {
    identifier: u16,
    sequence_number: u16,
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpRedirect {
    gateway_address: IPv4Address,
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpUnsupported {
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "hex::serde::serialize"
    )]
    unsupported: Vec<u8>,
}

/// Structure representing the ICMP Header
#[derive(Default, Debug, Serialize)]
pub struct ICMP {
    #[serde(rename = "type")]
    icmp_type: u8,
    code: u8,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u16")]
    checksum: u16,
    #[serde(flatten)]
    rest_of_header: IcmpType,
}

impl ICMP {
    pub(crate) fn creator() -> Box<dyn Layer + Send> {
        Box::<ICMP>::default()
    }
}

impl Layer for ICMP {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        let decoded;

        if bytes.len() < ICMP_HEADER_LENGTH {
            return Err(Error::TooShort {
                required: ICMP_HEADER_LENGTH,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }

        // decode type, code and checksum
        self.icmp_type = u8::from_be(bytes[0]);
        self.code = u8::from_be(bytes[1]);
        self.checksum = (bytes[2] as u16) << 8 | (bytes[3] as u16);

        // process the next 4 bytes depending on the type of ICMP packet
        self.rest_of_header = match self.icmp_type {
            ICMP_ECHO_REPLY => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                decoded = 8;
                IcmpType::EchoReply(IcmpEcho {
                    identifier,
                    sequence_number,
                })
            }
            ICMP_ECHO_REQUEST => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                decoded = 8;
                IcmpType::EchoRequest(IcmpEcho {
                    identifier,
                    sequence_number,
                })
            }
            ICMP_REDIRECT => {
                decoded = 8;
                IcmpType::Redirect(IcmpRedirect {
                    gateway_address: bytes[4..8].try_into().unwrap(),
                })
            }
            ICMP_DESTINATION_UNREACHABLE | ICMP_SOURCE_QUENCH | ICMP_TIME_EXCEEDED => {
                decoded = 8;
                IcmpType::Empty
            }
            _ => {
                decoded = bytes.len();
                IcmpType::Unsupported(IcmpUnsupported {
                    unsupported: bytes[4..].to_vec(),
                })
            }
        };
        Ok((None, decoded))
    }

    fn name(&self) -> &'static str {
        "ICMP"
    }

    fn short_name(&self) -> &'static str {
        "icmp"
    }
}

#[cfg(test)]
mod tests {
    use crate::layers;
    use crate::{Layer, Packet, ENCAP_TYPE_ETH};

    #[test]
    fn parse_valid_icmp_packet() {
        let _ = layers::register_defaults();

        let icmp_packet = vec![
            0x00, 0x20, 0x78, 0xe1, 0x5a, 0x80, 0x00, 0x10, 0x7b, 0x81, 0x43, 0xe3, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x38, 0x62, 0x3d, 0x00, 0x00, 0xff, 0x01, 0xd8, 0x1e, 0x0a, 0x02,
            0x63, 0x63, 0x0a, 0x02, 0x0a, 0x02, 0x05, 0x01, 0x38, 0x3e, 0x0a, 0x02, 0x63, 0x62,
            0x45, 0x00, 0x00, 0x3c, 0x3a, 0x00, 0x00, 0x00, 0x1f, 0x01, 0xfc, 0xb3, 0x0a, 0x02,
            0x0a, 0x02, 0x0a, 0x03, 0x47, 0x07, 0x08, 0x00, 0x1a, 0x5c, 0x02, 0x00, 0x31, 0x00,
        ];

        let mut icmp: Box<dyn Layer> = Box::new(super::ICMP::default());

        let p = icmp.decode_bytes(&icmp_packet[34..]);
        assert!(p.is_ok(), "{:#?}", icmp);
    }

    #[test]
    fn test_icmp_parse_regression() {
        let _ = layers::register_defaults();

        let test_icmp_packet = vec![
            0x00, 0x20, 0x78, 0xe1, 0x5a, 0x80, 0x00, 0x10, 0x7b, 0x81, 0x43, 0xe3, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x38, 0x62, 0x3d, 0x00, 0x00, 0xff, 0x01, 0xd8, 0x1e, 0x0a, 0x02,
            0x63, 0x63, 0x0a, 0x02, 0x0a, 0x02, 0x05, 0x01, 0x38, 0x3e, 0x0a, 0x02, 0x63, 0x62,
            0x45, 0x00, 0x00, 0x3c, 0x3a, 0x00, 0x00, 0x00, 0x1f, 0x01, 0xfc, 0xb3, 0x0a, 0x02,
            0x0a, 0x02, 0x0a, 0x03, 0x47, 0x07, 0x08, 0x00, 0x1a, 0x5c, 0x02, 0x00, 0x31, 0x00,
        ];

        let p = Packet::from_bytes(&test_icmp_packet, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();
        assert!(p.layers.len() == 3, "{:#?}", p);
    }
}
