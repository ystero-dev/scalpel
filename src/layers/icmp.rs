//! ICMP Datagram

use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layers::ipv4;
use crate::types::IPv4Address;
use crate::Layer;

/// IANA Assigned protocol number for ICMP
pub const IPPROTO_ICMP: u8 = 1_u8;

// Register ICMP with Protocol Handler in IPv4
pub(crate) fn register_defaults() -> Result<(), Error> {
    ipv4::register_protocol(IPPROTO_ICMP, ICMP::creator)
}

#[derive(Default, Debug, Serialize)]
#[serde(untagged)]
pub enum IcmpType {
    #[default]
    Unused,
    Echo(IcmpEcho),
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

/// Structure representing the ICMP Header
#[derive(Default, Debug, Serialize)]
pub struct ICMP {
    #[serde(rename = "type")]
    icmp_type: u8,
    code: u8,
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

        if bytes.len() < 8 {
            return Err(Error::TooShort {
                required: 8,
                available: bytes.len(),
                data: hex::encode(bytes)
            })
        }

        // decode type, code and checksum
        self.icmp_type = u8::from_be(bytes[0]);
        self.code = u8::from_be(bytes[1]);
        self.checksum = (bytes[2] as u16) << 8 | (bytes[3] as u16);

        // process the next 4 bytes depending on the type of ICMP packet
        self.rest_of_header = match self.icmp_type {
            0 | 8 | 13 | 14 | 15 | 16 => {
                let identifier = (bytes[4] as u16) << 8 | (bytes[5] as u16);
                let sequence_number = (bytes[6] as u16) << 8 | (bytes[7] as u16);
                IcmpType::Echo(IcmpEcho {
                    identifier,
                    sequence_number,
                })
            }
            5 => {
                IcmpType::Redirect(IcmpRedirect {
                    gateway_address: bytes[4..8].try_into().unwrap(),
                })
            }
            3 | 4 | 11 | _ => {
                IcmpType::Unused
            }
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
