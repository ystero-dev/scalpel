//! Scalpel: A crate for dissecting and sculpting Packets.
//!
//! A Basic unit in a scalpel is a `Packet`, a struct representing a Packet captured (and
//! dissected) from the wire.
//!
//! A packet is a collection of `Layer`s. Each `Layer` is a struct implementing the `Layer` trait

mod ethernet;

use std::fmt::Debug;
use std::rc::Rc;

#[derive(Debug)]
pub struct Error;

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}

pub enum EncapType {
    EncapTypeEthernet,
}

#[derive(Debug, Default)]
struct Timestamp {
    secs: i64,
    nsecs: i64,
}

#[derive(Debug, Default)]
pub struct Packet<'a> {
    data: Option<&'a [u8]>,
    meta: PacketMetadata,
}

pub trait Layer<'a>: Debug {
    fn from_u8<'b>(&'a mut self, bytes: &'b [u8]) -> Result<(Option<Rc<dyn Layer>>, usize), Error>;
}

#[derive(Debug, Default)]
pub struct PacketMetadata {
    timestamp: Timestamp,
    inface: i8,
    len: u16,
    caplen: u16,
}

impl<'a> Packet<'a> {
    fn from_u8(_bytes: &'a [u8], _encap: EncapType) -> Self {
        let p = Default::default();

        p
    }
}

impl<'l> Layer<'l> for Packet<'l> {
    fn from_u8<'b>(
        &'l mut self,
        _bytes: &'b [u8],
    ) -> Result<(Option<Rc<dyn Layer>>, usize), Error> {
        Ok((Some(Rc::new(ethernet::Ethernet::default())), 0))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
