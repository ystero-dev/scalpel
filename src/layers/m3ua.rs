//! M3UA Layer in SCTP
//!
//! Basic header handling for MTP3 User Application Protocol (RFC-4666).

use core::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layer::Layer;

use crate::layers::sctp;

pub const PROTO_M3UA: u32 = 3u32;

// Register ourselves With IPv4 and IPv6
pub(crate) fn register_defaults() -> Result<(), Error> {
    sctp::register_datachunk_protocol(PROTO_M3UA, M3UA::creator)
}

#[derive(Debug, Default, Serialize)]
pub struct M3UA {
    version: u8,
    reserved: u8,
    msg_class: u8,
    msg_type: u8,
    msg_length: u32,

    #[serde(serialize_with = "hex::serde::serialize")]
    msg_data: Vec<u8>,
}

impl M3UA {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::new(M3UA::default())
    }
}

impl Layer for M3UA {
    fn from_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < 8 {
            return Err(Error::TooShort);
        }

        let mut start = 0;

        self.version = bytes[start];
        start += 1;

        self.reserved = bytes[start];
        start += 1;

        self.msg_class = bytes[start];
        start += 1;

        self.msg_type = bytes[start];
        start += 1;

        eprintln!(
            "start: {}, byte: {:x}, len: {}",
            start,
            bytes[start],
            bytes.len()
        );
        self.msg_length = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap());

        if bytes.len() < self.msg_length as usize {
            return Err(Error::TooShort);
        }

        let data_len = self.msg_length - 8;
        self.msg_data = bytes[start..start + data_len as usize].try_into().unwrap();

        Ok((None, self.msg_length as usize))
    }

    fn name(&self) -> &'static str {
        "M3UA"
    }

    fn short_name(&self) -> &'static str {
        "m3ua"
    }
}
