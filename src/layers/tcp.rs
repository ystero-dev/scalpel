//! TCP Layer
use core::convert::TryInto;

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::Serialize;

use crate::errors::Error;
use crate::types::LayerCreatorFn;
use crate::Layer;

use crate::layers::{ipv4, ipv6};

lazy_static! {
    static ref TCP_APPS_MAP: RwLock<HashMap<u16, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

/// TCP header length
pub const TCP_BASE_HDR_LEN: usize = 20_usize;

/// IANA Assigned protocol number for TCP
pub const IPPROTO_TCP: u8 = 6_u8;

// Register ourselves With IPv4 and IPv6
pub(crate) fn register_defaults() -> Result<(), Error> {
    lazy_static::initialize(&TCP_APPS_MAP);

    ipv4::register_protocol(IPPROTO_TCP, TCP::creator)?;
    ipv6::register_next_header(IPPROTO_TCP, TCP::creator)?;

    Ok(())
}

/// Register An App for decoding after TCP Layer
///
/// This is a public API function for an App whose dissector should be called after TCP Layer's if
/// the Source or Destination port matches one of the ports. For example HTTP Protocol layer would
/// register itself with port 80 with the TCP layer.
pub fn register_app(port: u16, app: LayerCreatorFn) -> Result<(), Error> {
    lazy_static::initialize(&TCP_APPS_MAP);

    let mut map = TCP_APPS_MAP.write().unwrap();

    if map.contains_key(&port) {
        return Err(Error::RegisterError(format!("TCP Port: {}", port)));
    }
    map.insert(port, app);

    Ok(())
}

/// Structure representing TCP Header
#[derive(Debug, Default, Serialize)]
pub struct TCP {
    src_port: u16,
    dst_port: u16,
    seq_no: u32,
    ack_no: u32,
    data_offset: u8,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u16")]
    flags: u16,
    window_size: u16,
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u16")]
    checksum: u16,
    urgent_ptr: u16,
}

impl TCP {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::<TCP>::default()
    }
}

impl Layer for TCP {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < TCP_BASE_HDR_LEN {
            return Err(Error::TooShort {
                required: TCP_BASE_HDR_LEN,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }

        self.src_port = (bytes[0] as u16) << 8 | (bytes[1] as u16);
        self.dst_port = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.seq_no = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        self.ack_no = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        self.data_offset = bytes[12] >> 4;
        self.flags = (bytes[12] as u16) << 8 | (bytes[13] as u16) & 0x01FF;
        self.window_size = (bytes[14] as u16) << 8 | (bytes[15] as u16);
        self.checksum = (bytes[16] as u16) << 8 | (bytes[17] as u16);
        self.urgent_ptr = (bytes[18] as u16) << 8 | (bytes[19] as u16);

        let map = TCP_APPS_MAP.read().unwrap();
        let mut app = map.get(&self.dst_port);
        if app.is_none() {
            app = map.get(&self.src_port);
        }
        match app {
            None => Ok((None, TCP_BASE_HDR_LEN)),
            Some(app_creator_fn) => Ok((Some(app_creator_fn()), TCP_BASE_HDR_LEN)),
        }
    }

    fn name(&self) -> &'static str {
        "TCP"
    }

    fn short_name(&self) -> &'static str {
        "tcp"
    }
}
