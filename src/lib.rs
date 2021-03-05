//! Scalpel: A crate for dissecting and sculpting Packets.
//!
//! A Basic unit in a scalpel is a `Packet`, a struct representing a Packet captured (and
//! dissected) from the wire.
//!
//! A packet is a collection of `Layer`s. Each `Layer` is a struct implementing the `Layer` trait

mod ethernet;
use ethernet::Ethernet;

use std::cell::RefCell;
use std::fmt::Debug;

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
    layers: Vec<Box<dyn Layer<'a>>>,
}

pub trait Layer<'a>: Debug {
    fn from_u8<'b>(&mut self, bytes: &'b [u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error>;
}

#[derive(Debug, Default)]
struct FakeLayer;

impl<'a> Layer<'a> for FakeLayer {
    fn from_u8<'b>(&mut self, _btes: &'b [u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        Ok((Some(Box::new(FakeLayer {})), 0))
    }
}
#[derive(Debug, Default)]
pub struct PacketMetadata {
    timestamp: Timestamp,
    inface: i8,
    len: u16,
    caplen: u16,
}

impl<'a> Packet<'a> {
    fn from_u8(bytes: &'a [u8], _encap: EncapType) -> Result<Self, Error> {
        let mut p = Packet::default();

        let eth = ethernet::Ethernet::default();

        let mut layer: RefCell<Box<dyn Layer>> = RefCell::new(Box::new(eth));
        let mut res: (Option<Box<dyn Layer>>, usize);
        let mut start = 0;
        loop {
            let mut decode_layer = layer.borrow_mut();

            // process it
            res = decode_layer.from_u8(&bytes[start..])?;

            if res.0.is_none() {
                let fake_boxed = Box::new(FakeLayer {});
                let boxed = std::mem::replace(&mut *decode_layer, fake_boxed);

                p.layers.push(boxed);
                break;
            }
            // if the layer exists, get it in a layer.
            let boxed = std::mem::replace(&mut *decode_layer, res.0.unwrap());
            start = res.1;

            // append the layer to layers.
            p.layers.push(boxed);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
