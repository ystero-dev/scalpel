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

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum IcmpType {
    #[serde[rename = "unsupported"]]
    Unsupported(IcmpUnsupported),
    Unused(IcmpUnused),
    EchoRequest(IcmpEcho),
    EchoReply(IcmpEcho),
    Redirect(IcmpRedirect),
}

impl Default for IcmpType {
    fn default() -> Self {
        IcmpType::Unsupported(IcmpUnsupported{unsupported: 0})
    }
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
pub struct IcmpUnused {
    unused: u32,
}

#[derive(Default, Debug, Serialize)]
pub struct IcmpUnsupported {
    unsupported: u32,
}



/// Structure representing the ICMP Header
#[derive(Default, Debug, Serialize)]
pub struct ICMP {
    #[serde(rename = "type")]
    icmp_type: u8,
    code: u8,
    checksum: String,
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
        self.checksum = hex::encode(&bytes[2..4]);

        // process the next 4 bytes depending on the type of ICMP packet
        self.rest_of_header = match self.icmp_type {
            ICMP_ECHO_REPLY => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                IcmpType::EchoReply(IcmpEcho {
                    identifier,
                    sequence_number,
                })
            }
            ICMP_ECHO_REQUEST => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                IcmpType::EchoRequest(IcmpEcho {
                    identifier,
                    sequence_number,
                })
            }
            ICMP_REDIRECT => IcmpType::Redirect(IcmpRedirect {
                gateway_address: bytes[4..8].try_into().unwrap(),
            }),
            ICMP_DESTINATION_UNREACHABLE | ICMP_SOURCE_QUENCH | ICMP_TIME_EXCEEDED => {
                IcmpType::Unused(IcmpUnused {
                    unused: (bytes[4] as u32) << 24
                        | (bytes[5] as u32) << 16
                        | (bytes[6] as u32) << 8
                        | (bytes[7] as u32),
                })
            }
            _ => IcmpType::Unsupported(IcmpUnsupported{
                unsupported: (bytes[4] as u32) << 24
                | (bytes[5] as u32) << 16
                | (bytes[6] as u32) << 8
                | (bytes[7] as u32)
            })
        };
        decoded = 8;
        Ok((None, decoded))
    }

    fn name(&self) -> &'static str {
        "ICMP"
    }

    fn short_name(&self) -> &'static str {
        "icmp"
    }
}
