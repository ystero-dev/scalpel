//! ICMPv6 Datagram

use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layers::ipv6;
use crate::types::IPv6Address;
use crate::Layer;

/// IANA Assigned protocol number for ICMP
pub const IPPROTO_ICMPV6: u8 = 58_u8;
/// ICMP header length
pub const ICMPV6_HEADER_LENGTH: usize = 8_usize;

// Register ICMPv6 with Protocol Handler in IPv6
pub(crate) fn register_defaults() -> Result<(), Error> {
    ipv6::register_next_header(IPPROTO_ICMPV6, ICMPv6::creator)
}

// defining the types
pub const ICMPV6_DESTINATION_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;

#[derive(Default, Debug, Serialize)]
#[serde(untagged)]
pub enum Icmpv6Type {
    #[default]
    Empty,
    Unsupported(Icmpv6Unsupported),
    #[serde[rename = "unsupported"]]
    EchoRequest(Icmpv6Echo),
    EchoReply(Icmpv6Echo),
    PacketSizeTooBig(Icmpv6PacketSizeTooBig),
    NeighborSolicitation(Icmpv6NeighborSolicitation),
}

#[derive(Default, Debug, Serialize)]
pub struct Icmpv6Echo {
    identifier: u16,
    sequence_number: u16,
}

#[derive(Default, Debug, Serialize)]
pub struct Icmpv6PacketSizeTooBig {
    mtu: u32,
}

#[derive(Default, Debug, Serialize)]
pub struct Icmpv6Unsupported {
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "hex::serde::serialize"
    )]
    unsupported: Vec<u8>,
}

#[derive(Default, Debug, Serialize)]
pub struct Icmpv6NeighborSolicitation {
    target_address: IPv6Address,
}

/// Structure representing the ICMPv6 Header
#[derive(Default, Debug, Serialize)]
pub struct ICMPv6 {
    #[serde(rename = "type")]
    icmp_type: u8,
    code: u8,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u16")]
    checksum: u16,
    #[serde(flatten)]
    rest_of_header: Icmpv6Type,
}

impl ICMPv6 {
    pub(crate) fn creator() -> Box<dyn Layer + Send> {
        Box::<ICMPv6>::default()
    }
}

impl Layer for ICMPv6 {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        let decoded;

        if bytes.len() < ICMPV6_HEADER_LENGTH {
            return Err(Error::TooShort {
                required: ICMPV6_HEADER_LENGTH,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }

        // decode type, code and checksum
        self.icmp_type = u8::from_be(bytes[0]);
        self.code = u8::from_be(bytes[1]);
        self.checksum = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.rest_of_header = match self.icmp_type {
            ICMPV6_ECHO_REQUEST => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                decoded = 8;
                Icmpv6Type::EchoReply(Icmpv6Echo {
                    identifier,
                    sequence_number,
                })
            }

            ICMPV6_ECHO_REPLY => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                decoded = 8;
                Icmpv6Type::EchoReply(Icmpv6Echo {
                    identifier,
                    sequence_number,
                })
            }

            ICMPV6_PACKET_TOO_BIG => {
                let mtu = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                decoded = 8;
                Icmpv6Type::PacketSizeTooBig(Icmpv6PacketSizeTooBig { mtu })
            }

            ICMPV6_DESTINATION_UNREACHABLE | ICMPV6_TIME_EXCEEDED => {
                decoded = 8;
                Icmpv6Type::Empty
            }

            ICMPV6_NEIGHBOR_SOLICITATION => {
                let target_address = bytes[8..24].try_into().unwrap();
                decoded = 24;
                Icmpv6Type::NeighborSolicitation(Icmpv6NeighborSolicitation { target_address })
            }

            _ => {
                decoded = bytes.len();
                Icmpv6Type::Unsupported(Icmpv6Unsupported {
                    unsupported: bytes[4..].to_vec(),
                })
            }
        };
        Ok((None, decoded))
    }
    fn name(&self) -> &'static str {
        "ICMPV6"
    }

    fn short_name(&self) -> &'static str {
        "icmpv6"
    }
}
