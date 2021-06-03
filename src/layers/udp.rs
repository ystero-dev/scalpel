//! UDP Layer

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

        self.src_port = (bytes[0] as u16) << 8 | (bytes[1] as u16);
        self.dst_port = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.length = (bytes[4] as u16) << 8 | (bytes[5] as u16);
        self.checksum = (bytes[6] as u16) << 8 | (bytes[7] as u16);

        Ok((None, UDP_HDR_LEN))
    }

    fn name(&self) -> &str {
        "UDP"
    }

    fn short_name(&self) -> &str {
        "udp"
    }
}
