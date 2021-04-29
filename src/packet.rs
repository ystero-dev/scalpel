//! Packet Structure

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Mutex;

use lazy_static::lazy_static;

use crate::layers::ethernet::{self, Ethernet};
use crate::types::{EncapType, LayerCreatorFn, ENCAP_TYPE_ETH};
use crate::Error;
use crate::{FakeLayer, Layer};

lazy_static! {
    // FIXME: Convert the following Mutex to RWLock? We only need to lock it when we are updating
    // the map and not when we are inserting into map. The inserting into Map will typically be
    // rare and usually init time activity. Is there a better way of handling this without lock?
    static ref ENCAP_TYPES_MAP: Mutex<HashMap<EncapType, LayerCreatorFn>> =
        Mutex::new(HashMap::new());
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
    unprocessed: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct PacketMetadata {
    timestamp: Timestamp,
    iface: i8,
    len: u16,
    caplen: u16,
}

impl<'a> Packet<'a> {
    /// Register well-known encodings
    ///
    /// Any 'application' using our crate, should call this functions first, to be able to dissect
    /// the packets.
    pub fn register_default_encap_types() -> Result<(), Error> {
        Self::register_encap_type(ENCAP_TYPE_ETH, Ethernet::creator)?;

        // For additional encodings, Add support here.
        // FIXME: Perhaps this should be generated through `build.rs` somehow.

        Ok(())
    }

    /// Register a new Layer 2 encoding
    ///
    /// Any 'crate' using the infrastucture, should call this function with their encoding type
    pub fn register_encap_type(encap: EncapType, creator: LayerCreatorFn) -> Result<(), Error> {
        let mut map = ENCAP_TYPES_MAP.lock().unwrap();
        if map.contains_key(&ENCAP_TYPE_ETH) {
            return Err(Error::RegisterError);
        }
        map.insert(encap, creator);

        Ok(())
    }

    /// Register All well-know defaults for each of the encap types
    ///
    /// Right now Ethernet is the only Encoding supported. When other encodings are supported, we
    /// should call their `register_defaults` as well.
    pub fn register_defaults() -> Result<(), Error> {
        ethernet::register_defaults()
    }

    fn from_u8(bytes: &'a [u8], encap: EncapType) -> Result<Self, Error> {
        let mut p = Packet::default();

        let l2: Box<dyn Layer>;
        {
            let map = ENCAP_TYPES_MAP.lock().unwrap();
            let creator_fn = map.get(&encap);
            if creator_fn.is_none() {
                let new: Vec<_> = bytes.into();
                let old = std::mem::replace(&mut p.unprocessed, new);

                return Ok(p);
            }

            l2 = creator_fn.unwrap()();
        }

        let layer: RefCell<Box<dyn Layer>> = RefCell::new(l2);
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
        if start != bytes.len() {
            let new: Vec<_> = bytes[start..].into();
            let old = std::mem::replace(&mut p.unprocessed, new);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn from_u8_fail_too_short() {
        Packet::register_default_encap_types();
        let p = Packet::from_u8("".as_bytes(), ENCAP_TYPE_ETH);

        assert!(p.is_err(), "{:?}", p.ok());
    }

    #[test]
    fn from_u8_success_eth_hdr_size() {
        Packet::register_default_encap_types();

        let p = Packet::from_u8(&[0; 14], ENCAP_TYPE_ETH);

        assert!(p.is_ok(), "{:?}", p.err());
    }
}
