//! Packet Structure

use std::cell::RefCell;
use std::fmt::Debug;

use crate::ethernet::Ethernet;
use crate::Error;
use crate::{FakeLayer, Layer};

pub enum EncapType {
    Ethernet,
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
    layers: Vec<Box<dyn Layer>>,
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

        let eth = Ethernet::default();

        let layer: RefCell<Box<dyn Layer>> = RefCell::new(Box::new(eth));
        let mut res: (Option<Box<dyn Layer>>, usize);
        let mut start = 0;
        loop {
            {
                let mut decode_layer = layer.borrow_mut();
                res = decode_layer.from_u8(&bytes[start..])?;
            }

            if res.0.is_none() {
                let fake_boxed = Box::new(FakeLayer {});
                let boxed = layer.replace(fake_boxed);

                p.layers.push(boxed);
                break;
            }

            // if the layer exists, get it in a layer.
            let boxed = layer.replace(res.0.unwrap());
            start += res.1;

            // append the layer to layers.
            p.layers.push(boxed);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn from_u8_fail_too_short() {
        let p = Packet::from_u8("".as_bytes(), EncapType::Ethernet);

        assert!(p.is_err(), "{:?}", p.ok());
    }

    #[test]
    fn from_u8_success_eth_hdr_size() {
        let p = Packet::from_u8(&[0; 14], EncapType::Ethernet);

        assert!(p.is_ok(), "{:?}", p.err());
    }
}
