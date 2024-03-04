//! ICMP Datagram

use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layers::ipv4;
use crate::types::IPv4Address;
use crate::Layer;

use super::ipv4::IPv4;

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
pub const ICMP_TIMESTAMP_REQUEST: u8 = 13_u8;
pub const ICMP_TIMESTAMP_REPLY: u8 = 14_u8;


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
    TimestampRequest(IcmpEcho),
    TimestampReply(IcmpEcho),
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

#[derive(Default, Debug, Serialize)]
#[serde(untagged)]
pub enum IcmpData {
    #[default]
    None,
    Unknown(IcmpUnknownData),
    Timestamp(IcmpTimestampData),
    Error(IcmpOriginalDatagramPortion),
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpUnknownData {
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "hex::serde::serialize"
    )]
    data: Vec<u8>,
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpTimestampData {
    originate_timestamp: u32,
    recieve_timestamp: u32,
    transmit_timestamp: u32,
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpOriginalDatagramPortion {
    ip_header: IPv4,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "hex::serde::serialize"
    )]
    data:  Vec<u8>,
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
    #[serde(flatten)]
    data: IcmpData,
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
        let mut decoded;

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
            ICMP_TIMESTAMP_REQUEST => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                decoded = 8;
                IcmpType::TimestampRequest(IcmpEcho {
                    identifier,
                    sequence_number,
                })
            }
            ICMP_TIMESTAMP_REPLY => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                decoded = 8;
                IcmpType::TimestampReply(IcmpEcho {
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


        self.data = match self.icmp_type {
            ICMP_ECHO_REPLY | ICMP_ECHO_REQUEST => {
                decoded = bytes.len();
                IcmpData::Unknown(IcmpUnknownData { data: bytes[8..].to_vec() })
            }
            ICMP_DESTINATION_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_SOURCE_QUENCH => {
                let mut ip_header: IPv4 = IPv4::default();
                let (_, processed) = ip_header.decode_bytes(&bytes[8..])?;
                let data_offset = decoded + processed;
                decoded = bytes.len();
                IcmpData::Error(IcmpOriginalDatagramPortion{
                    ip_header,
                    data: bytes[data_offset..].try_into().unwrap()
                })
            }
            ICMP_TIMESTAMP_REPLY | ICMP_TIMESTAMP_REQUEST => {
                decoded += 12;
                let originate_timestamp = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                let recieve_timestamp = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
                let transmit_timestamp = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
                IcmpData::Timestamp(IcmpTimestampData{
                    originate_timestamp,
                    recieve_timestamp,
                    transmit_timestamp,
                })
            }
            _ => IcmpData::None
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
    use serde_json::json;

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

    #[test]
    fn parse_icmp_redirect_packet() {
        let _ = layers::register_defaults();

        let icmp_redirect_packet = vec![
            0x00, 0x20, 0x78, 0xe1, 0x5a, 0x80, 0x00, 0x10, 0x7b, 0x81, 0x43, 0xe3, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x38, 0x62, 0x3d, 0x00, 0x00, 0xff, 0x01, 0xd8, 0x1e, 0x0a, 0x02,
            0x63, 0x63, 0x0a, 0x02, 0x0a, 0x02, 0x05, 0x01, 0x38, 0x3e, 0x0a, 0x02, 0x63, 0x62,
            0x45, 0x00, 0x00, 0x3c, 0x3a, 0x00, 0x00, 0x00, 0x1f, 0x01, 0xfc, 0xb3, 0x0a, 0x02,
            0x0a, 0x02, 0x0a, 0x03, 0x47, 0x07, 0x08, 0x00, 0x1a, 0x5c, 0x02, 0x00, 0x31, 0x00,
        ];

        let p = Packet::from_bytes(&icmp_redirect_packet, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();

        let icmp_packet = serde_json::to_value(&p.layers[2]).unwrap();
        assert_eq!(icmp_packet.get("type"), Some(&json!(5)));
        assert_eq!(icmp_packet.get("code"), Some(&json!(1)));
        assert_eq!(icmp_packet.get("checksum"), Some(&json!("0x383e")));
        assert_eq!(
            icmp_packet.get("gateway_address"),
            Some(&json!("10.2.99.98"))
        );
    }

    #[test]
    fn parse_icmp_echo_packet() {
        let _ = layers::register_defaults();

        let icmp_echo_packet = vec![
            0x50, 0xeb, 0x1a, 0x90, 0x61, 0x32, 0xd4, 0x6a, 0x6a, 0xb4, 0x62, 0x0d, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x54, 0x92, 0xe0, 0x40, 0x00, 0x40, 0x01, 0x49, 0x56, 0x0a, 0x64,
            0x01, 0xb0, 0x8e, 0xfa, 0xc3, 0x64, 0x08, 0x00, 0x98, 0xff, 0x00, 0x02, 0x00, 0x02,
            0x9d, 0x25, 0xda, 0x65, 0x00, 0x00, 0x00, 0x00, 0x20, 0x9e, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];

        let p = Packet::from_bytes(&icmp_echo_packet, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();

        let icmp_packet = serde_json::to_value(&p.layers[2]).unwrap();
        assert_eq!(icmp_packet.get("type"), Some(&json!(8)));
        assert_eq!(icmp_packet.get("code"), Some(&json!(0)));
        assert_eq!(icmp_packet.get("checksum"), Some(&json!("0x98ff")));
        assert_eq!(icmp_packet.get("identifier"), Some(&json!(2)));
        assert_eq!(icmp_packet.get("sequence_number"), Some(&json!(2)));
    }

    #[test]
    fn parse_icmp_destination_unreachable_packet() {
        let _ = layers::register_defaults();

        let icmp_destination_unreachable_packet = vec![
            0xca, 0x01, 0x0c, 0x68, 0x00, 0x08, 0xca, 0x00, 0x0c, 0x68, 0x00, 0x08, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x38, 0x00, 0x03, 0x00, 0x00, 0xff, 0x01, 0xa3, 0xbd, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x01, 0x02, 0x02, 0x03, 0x01, 0x2e, 0xfc, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x00, 0x00, 0x64, 0x00, 0x05, 0x00, 0x00, 0xfe, 0x01, 0xae, 0x8f, 0x0a, 0x01,
            0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0xc6, 0x01, 0x00, 0x01, 0x00, 0x00,
        ];

        let p = Packet::from_bytes(&icmp_destination_unreachable_packet, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();

        let icmp_packet = serde_json::to_value(&p.layers[2]).unwrap();
        assert_eq!(icmp_packet.get("type"), Some(&json!(3)));
        assert_eq!(icmp_packet.get("code"), Some(&json!(1)));
        assert_eq!(icmp_packet.get("checksum"), Some(&json!("0x2efc")));
    }

    #[test]
    fn parse_timestamp_icmp_type(){
        let _ = layers::register_defaults();

        let icmp_timestamp_packet = vec![
            0x00, 0x11, 0x2f, 0x36, 0x8c, 0xda, 0x00, 0xa0, 0xd1, 0xbe, 0x97, 0xdd, 0x08, 0x00, 0x45,
            0x00, 0x00, 0x28, 0x0f, 0x3c, 0x00, 0x00, 0x80, 0x01, 0xa9, 0x7b, 0xc0, 0xa8, 0x00, 0x67,
            0xc0, 0xa8, 0x00, 0x66, 0x0e, 0x00, 0xd3, 0x11, 0x39, 0x30, 0x00, 0x00, 0x00, 0xf6, 0x36,
            0x59, 0x61, 0x36, 0xf6, 0x00, 0x61, 0x36, 0xf6, 0x00,
        ];

        let p = Packet::from_bytes(&icmp_timestamp_packet, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();

        let icmp_packet = serde_json::to_value(&p.layers[2]).unwrap();
        assert_eq!(icmp_packet.get("type"), Some(&json!(14)));
        assert_eq!(icmp_packet.get("code"), Some(&json!(0)));
        assert_eq!(icmp_packet.get("checksum"), Some(&json!("0xd311")));
        assert_eq!(icmp_packet.get("identifier"), Some(&json!(14640)));
        assert_eq!(icmp_packet.get("sequence_number"), Some(&json!(0)));
        assert_eq!(icmp_packet.get("originate_timestamp"), Some(&json!(16135769)));
        assert_eq!(icmp_packet.get("recieve_timestamp"), Some(&json!(1630991872)));
        assert_eq!(icmp_packet.get("transmit_timestamp"), Some(&json!(1630991872)));
    }

    #[test]
    fn parse_unsupported_icmp_type(){
        let _ = layers::register_defaults();

        let icmp_unsupported_packet = vec![
            0x00, 0xa0, 0xd1, 0xbe, 0x97, 0xdd, 0x00, 0x11, 
            0x2f, 0x36, 0x8c, 0xda, 0x08, 0x00, 0x45, 0x00, 
            0x00, 0x28, 0x8d, 0xff, 0x00, 0x00, 0x80, 0x01, 
            0x2a, 0xb8, 0xc0, 0xa8, 0x00, 0x66, 0xc0, 0xa8, 
            0x00, 0x67, 0x0c, 0x00, 0x94, 0xe3, 0x39, 0x30, 
            0x00, 0x00, 0x00, 0xf6, 0x23, 0xf6, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        let p = Packet::from_bytes(&icmp_unsupported_packet, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();
        let icmp_packet = serde_json::to_value(&p.layers[2]).unwrap();
        assert_eq!(icmp_packet.get("type"), Some(&json!(12)));
        assert_eq!(icmp_packet.get("code"), Some(&json!(0)));
        assert_eq!(icmp_packet.get("checksum"), Some(&json!("0x94e3")));
        assert_eq!(icmp_packet.get("unsupported"), Some(&json!("3930000000f623f60000000000000000")));
    }
}
