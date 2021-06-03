//! UDP Layer

use core::convert::TryInto as _;

use crate::errors::Error;
use crate::layer::Layer;

use crate::layers::{ipv4, ipv6};

/// UDP header length
pub const UDP_HDR_LEN: usize = 8_usize;
/// IANA Assigned protocol number for UDP
pub const IPPROTO_UDP: u8 = 17_u8;

/// Register UDP with Protocol Handler in IPv4 and IPv6
pub fn register_defaults() -> Result<(), Error> {
    ipv4::register_protocol(IPPROTO_UDP, UDP::creator)?;
    ipv6::register_next_header(IPPROTO_UDP, UDP::creator)?;

    Ok(())
}

#[derive(Debug, Default, Clone)]
struct UDP {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UDP {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(UDP::default())
    }
}

impl Layer for UDP {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        if bytes.len() < 8 {
            return Err(Error::TooShort);
        }

        self.src_port = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        self.dst_port = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        self.length = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        self.checksum = u16::from_be_bytes(bytes[6..8].try_into().unwrap());

        Ok((None, UDP_HDR_LEN))
    }

    fn name(&self) -> &str {
        "UDP"
    }

    fn short_name(&self) -> &str {
        "udp"
    }
}
