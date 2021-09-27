//! UDP Layer

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::Serialize;

use crate::errors::Error;
use crate::layer::Layer;
use crate::types::LayerCreatorFn;

use crate::layers::{ipv4, ipv6};

lazy_static! {
    static ref UDP_APPS_MAP: RwLock<HashMap<u16, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

/// UDP header length
pub const UDP_HDR_LEN: usize = 8_usize;
/// IANA Assigned protocol number for UDP
pub const IPPROTO_UDP: u8 = 17_u8;

// Register UDP with Protocol Handler in IPv4 and IPv6
pub(crate) fn register_defaults() -> Result<(), Error> {
    ipv4::register_protocol(IPPROTO_UDP, UDP::creator)?;
    ipv6::register_next_header(IPPROTO_UDP, UDP::creator)?;

    Ok(())
}

/// API for an Application to register with us
///
/// This is a public API function for an App whose dissector should be called after UDP Layer's if
/// the Source or Destination port matches one of the ports.
pub fn register_app(port: u16, app: LayerCreatorFn) -> Result<(), Error> {
    let mut map = UDP_APPS_MAP.write().unwrap();

    if map.contains_key(&port) {
        return Err(Error::RegisterError);
    }
    map.insert(port, app);

    Ok(())
}

#[derive(Debug, Default, Serialize)]
pub struct UDP {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UDP {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::new(UDP::default())
    }
}

impl Layer for UDP {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < UDP_HDR_LEN {
            return Err(Error::TooShort);
        }

        self.src_port = (bytes[0] as u16) << 8 | (bytes[1] as u16);
        self.dst_port = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.length = (bytes[4] as u16) << 8 | (bytes[5] as u16);
        self.checksum = (bytes[6] as u16) << 8 | (bytes[7] as u16);

        let map = UDP_APPS_MAP.read().unwrap();
        let mut app = map.get(&self.dst_port);
        if app.is_none() {
            app = map.get(&self.src_port);
        }
        if app.is_none() {
            Ok((None, UDP_HDR_LEN))
        } else {
            let app_creator = app.unwrap();
            Ok((Some(app_creator()), UDP_HDR_LEN))
        }
    }

    fn name(&self) -> &'static str {
        "UDP"
    }

    fn short_name(&self) -> &'static str {
        "udp"
    }
}
