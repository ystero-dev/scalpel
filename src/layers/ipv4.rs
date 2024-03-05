//! IPv4 Layer

use core::convert::TryInto as _;

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::Serialize;

use crate::errors::Error;
use crate::types::{IPv4Address, LayerCreatorFn};
use crate::Layer;

/// Basic Length of the IPv4 Header when no options are present
pub const IPV4_BASE_HEADER_LENGTH: usize = 20_usize;

lazy_static! {
    static ref PROTOCOLS_MAP: RwLock<HashMap<u8, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

// Register ourselves to well-known Layer 2
//
// Right now only Ethernet is Supported
pub(crate) fn register_defaults() -> Result<(), Error> {
    use crate::layers::ethernet::register_ethertype;

    lazy_static::initialize(&PROTOCOLS_MAP);

    register_ethertype(crate::types::ETHERTYPE_IP, IPv4::creator)?;

    Ok(())
}

/// Register a Transport Protocol for dissection.
///
/// Higher level protocols should call this function to register themselves for decoding with the
/// IPv4 Layer. For example, [TCP Protocol][`crate::layers::tcp`] would call this function with a
/// protocol number 6 and similarly [UDP Protocol][`crate::layers::udp`] would call this function
/// with a protocol number of 17.
pub fn register_protocol(proto: u8, creator: LayerCreatorFn) -> Result<(), Error> {
    lazy_static::initialize(&PROTOCOLS_MAP);

    let mut map = PROTOCOLS_MAP.write().unwrap();
    if map.contains_key(&proto) {
        return Err(Error::RegisterError(format!("proto: {}", proto)));
    }
    map.insert(proto, creator);

    Ok(())
}

// Option Structs
#[derive(Debug, Serialize, PartialEq)]
struct IPOthers {
    #[serde(rename = "type")]
    type_: u8,
    len: u8,
    data: Vec<u8>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "type")]
pub enum IPOption {
    EOOL,
    NOP,
    RR { ptr: u8, route: Vec<IPv4Address> },
    // MTUP,
    // MTUR,
    Other { value: u8, len: u8, data: Vec<u8> },
}

#[derive(Debug, Default, Serialize)]
pub struct IPv4 {
    version: u8,
    hdr_len: u8,
    tos: u8,
    len: u16,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u16")]
    id: u16,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    flags: u8,
    frag_offset: u16,
    ttl: u8,
    proto: u8,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u16")]
    checksum: u16,
    src_addr: IPv4Address,
    dst_addr: IPv4Address,
    options: Vec<IPOption>,
}

impl IPv4 {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::<IPv4>::default()
    }
}

impl IPv4 {
    fn options_from_bytes(&mut self, bytes: &[u8], mut remaining: usize) -> Result<usize, Error> {
        let mut i = 0_usize;
        let mut done = false;

        while !done {
            let (option, consumed) = Self::option_from_bytes(&bytes[i..], remaining)?;
            i += consumed;
            remaining -= consumed;
            if remaining == 0 || option == IPOption::EOOL {
                done = true;
            }
            self.options.push(option);
        }

        Ok(i)
    }

    fn option_from_bytes(bytes: &[u8], mut remaining: usize) -> Result<(IPOption, usize), Error> {
        let mut i = 0_usize;
        let value = bytes[0];

        // from: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
        let option = match value {
            0 => {
                i += 2;
                remaining -= 2;
                IPOption::EOOL
            }
            1 => {
                i += 2;
                remaining -= 2;
                IPOption::NOP
            }
            7 => {
                let ((len, data), consumed) = Self::option_data_from_bytes(&bytes[i..], remaining)?;
                i += consumed;
                remaining -= consumed;

                let ptr = data[0];
                let mut route = Vec::new();

                {
                    // ptr within data
                    let ptr = ptr as usize - 3;
                    let mut i = 1_usize;
                    // run till either data is exhausted or we hit ptr
                    while i + 2 < len as usize && i < ptr {
                        let addr = data[i..i + 4].try_into().unwrap();
                        route.push(addr);
                        i += 4;
                    }
                }

                IPOption::RR { ptr, route }
            }
            11 => {
                todo!("MTUP")
            }
            12 => {
                todo!("MTUR")
            }
            value => {
                let ((len, data), consumed) = Self::option_data_from_bytes(&bytes[i..], remaining)?;
                i += consumed;
                remaining -= consumed;

                IPOption::Other {
                    value,
                    len,
                    data: data.into(),
                }
            }
        };

        Ok((option, i))
    }

    fn option_data_from_bytes(
        bytes: &[u8],
        mut remaining: usize,
    ) -> Result<((u8, &[u8]), usize), Error> {
        // skip first byte(type)
        let mut i = 1_usize;
        remaining -= 1;
        // check if we have enough bytes for length field
        if remaining < 1 {
            return Err(Error::TooShort {
                required: 1,
                available: remaining,
                data: hex::encode(bytes),
            });
        }
        // len also includes the type and len octets
        let len = bytes[i] as usize;
        i += 1;
        remaining -= 1;

        if remaining + 2 < len {
            return Err(Error::TooShort {
                required: len,
                available: remaining + 2,
                data: hex::encode(bytes),
            });
        }
        let data = &bytes[i..i + len - 2];
        i += len - 2;
        remaining -= len - 2;

        Ok(((len as u8, data), i))
    }
}

impl Layer for IPv4 {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        let mut decoded = 0_usize;
        let mut remaining = bytes.len();

        self.version = bytes[0] >> 4;
        self.hdr_len = bytes[0] & 0x0f;
        // Length is in 4 octets
        if bytes.len() < (self.hdr_len * 4).into() {
            return Err(Error::TooShort {
                required: self.hdr_len as usize * 4,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }
        self.tos = bytes[1];
        self.len = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        self.id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let flags_offset = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        self.flags = (flags_offset >> 13) as u8;
        self.frag_offset = flags_offset & 0x1fff;
        self.ttl = bytes[8];
        self.proto = bytes[9];
        self.checksum = (bytes[10] as u16) << 8 | (bytes[11] as u16);
        self.src_addr = bytes[12..16].try_into().unwrap();
        self.dst_addr = bytes[16..20].try_into().unwrap();

        decoded += IPV4_BASE_HEADER_LENGTH;
        remaining -= IPV4_BASE_HEADER_LENGTH;

        // check if enough bytes exist for options
        if bytes.len() < self.hdr_len as usize * 4 {
            return Err(Error::TooShort {
                required: self.hdr_len as usize * 4,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }

        let consumed = self.options_from_bytes(&bytes[decoded..], remaining)?;
        decoded += consumed;
        remaining -= consumed;

        let map = PROTOCOLS_MAP.read().unwrap();
        let layer = map.get(&self.proto);

        match layer {
            None => Ok((None, decoded)),
            Some(l4_creator) => Ok((Some(l4_creator()), decoded)),
        }
    }

    fn name(&self) -> &'static str {
        "IPv4"
    }

    fn short_name(&self) -> &'static str {
        "ip"
    }
}
