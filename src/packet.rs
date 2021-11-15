//! Packet Structure

use core::cell::RefCell;
use core::fmt::Debug;

// FIXME: Should work with `no_std`
use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::{ser::SerializeStruct, Serialize, Serializer};

use crate::errors::Error;
use crate::layer::{EmptyLayer, Layer};
use crate::types::{EncapType, LayerCreatorFn, ENCAP_TYPE_ETH};

use pyo3::prelude::*;

lazy_static! {
    static ref ENCAP_TYPES_MAP: RwLock<HashMap<EncapType, LayerCreatorFn>> =
        RwLock::new(HashMap::new());
}

#[derive(Debug, Default, Serialize)]
struct Timestamp {
    secs: i64,
    nsecs: i64,
}

/// [`Packet`] is a central structure in `scalpel` containing the decoded data and some metadata.
///
/// When a byte-stream is 'dissected' by scalpel, it creates a `Packet` structure that contains the
/// following information.
///  * `data` : Optional 'data' from which this packet is constructed.
///  * `meta` : Metadata associated with the packet. This contains information like timestamp,
///             interface identifier where the data was captured etc. see `PacketMetadata` for
///             details.
///  * `layers`: A Vector of Opaque structures, each implementing the `Layer` trait. For example
///              Each of the following is a Layer - `Ethernet`, `IPv4`, `TCP` etc.
///  * `unprocessed`: The part of the original byte-stream that is not processed and captured into
///                   `layers` above.
#[pyclass]
#[derive(Debug, Default, Serialize)]
pub struct Packet {
    pub meta: PacketMetadata,
    #[serde(serialize_with = "serialize_layers_as_struct")]
    pub layers: Vec<Box<dyn Layer + Send>>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "hex::serde::serialize"
    )]
    pub unprocessed: Vec<u8>,
}

// Function used to serialize layers in a given packet
//
// This is mainly used for JSON serlialization. The layers are serialized as -
//
// ```
//  layers: {
//      'ethernet' : {
//          ...
//      },
//      'ip': {
//          ...
//      },
//  }
//  ```
fn serialize_layers_as_struct<S>(
    layers: &Vec<Box<dyn Layer + Send>>,
    serializer: S,
) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("layers", layers.len())?;
    for layer in layers {
        state.serialize_field(layer.short_name(), layer)?;
    }
    state.end()
}

/// Metadata associated with the Packet.
#[derive(Debug, Default, Serialize)]
pub struct PacketMetadata {
    /// Capture timestamp
    timestamp: Timestamp,
    /// Interface ID
    iface: i8,
    /// Actual length on the wire
    len: u16,
    /// Capture length
    caplen: u16,
}

impl Packet {
    /// Register a new Layer 2 encoding
    ///
    /// Each of the Layer 2 structures, follow their own 'encoding' mechanism, to determine which
    /// subsequent layers are to be decoded first the Layer 2 needs to be determined. Each of the
    /// Layer 2 Layers (eg. Ethernet) will have to register for this decode themselves.
    ///
    /// A Global Map of Layer 2 Encoding Type  as `Key` and Decoding Function as 'value' is
    /// maintained. Registering a Layer 2 decoder will cause an entry in this map to be created.
    /// Support for registration of certain Layer 2 decoders (eg. Ethernet) is implemented in
    /// `scalpel` itself. A client will want to register it's own decoding function by using this
    /// API.
    pub fn register_encap_type(encap: EncapType, creator: LayerCreatorFn) -> Result<(), Error> {
        let mut map = ENCAP_TYPES_MAP.write().unwrap();
        if map.contains_key(&ENCAP_TYPE_ETH) {
            return Err(Error::RegisterError);
        }
        map.insert(encap, creator);

        Ok(())
    }

    /// Create a [`Packet`] from a u8 slice.
    ///
    /// This is the main 'decoder' function. An application would typically call
    /// `Packet::from_bytes`. The `encap` parameter passed is the one that is used by the Layer 2
    /// to register itself in the [`Packet::register_encap_type`] function. Upon successful
    /// decoding a `Packet` structure is returned on success or error if any in decoding the packet
    /// is returned.
    pub fn from_bytes(bytes: &[u8], encap: EncapType) -> Result<Self, Error> {
        let mut p = Packet::default();

        let l2: Box<dyn Layer + Send>;
        {
            let map = ENCAP_TYPES_MAP.read().unwrap();
            let creator_fn = map.get(&encap);
            if creator_fn.is_none() {
                let new: Vec<_> = bytes.into();
                let _ = core::mem::replace(&mut p.unprocessed, new);

                return Ok(p);
            }

            l2 = creator_fn.unwrap()();
        }

        let layer: RefCell<Box<dyn Layer + Send>> = RefCell::new(l2);
        let mut res: (Option<Box<dyn Layer + Send>>, usize);
        let mut start = 0;
        loop {
            {
                let mut decode_layer = layer.borrow_mut();
                res = decode_layer.from_bytes(&bytes[start..])?;
            }

            if res.0.is_none() {
                // We need to get out the 'last' layer and hence replace it with an EmptyLayer that
                // is kept in the `RefCell` which will get dropped later. Empty Layer is like
                // `Default::default()` for `Box<dyn Layer>`
                let boxed = layer.replace(Box::new(EmptyLayer {}));

                p.layers.push(boxed);
                start += res.1;
                break;
            }

            // if the layer exists, get it in a layer.
            let boxed = layer.replace(res.0.unwrap());
            start += res.1;

            // append the layer to layers.
            p.layers.push(boxed);
        }
        if start != bytes.len() {
            let _ = core::mem::replace(&mut p.unprocessed, bytes[start..].to_vec());
        }
        Ok(p)
    }
}

// Python Bindings
#[pymethods]
impl Packet {
    #[staticmethod]
    fn from_bytes_py(bytes: &[u8], encap: EncapType) -> PyResult<Self> {
        let _ = crate::layers::register_defaults();

        Self::from_bytes(bytes, encap).map_err(|e| e.into())
    }

    fn as_json(&self) -> PyResult<String> {
        Ok(serde_json::to_string_pretty(self).unwrap())
    }
}

pub(crate) fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Packet>()?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use hex;

    use crate::layers;
    use crate::layers::ethernet::ETH_HEADER_LEN;
    use crate::layers::ipv4::IPV4_BASE_HDR_LEN;
    use crate::layers::ipv6::IPV6_BASE_HDR_LEN;
    use crate::layers::tcp::TCP_BASE_HDR_LEN;

    #[test]
    fn from_bytes_fail_too_short() {
        let _ = crate::layers::register_defaults();

        let p = Packet::from_bytes("".as_bytes(), ENCAP_TYPE_ETH);

        assert!(p.is_err(), "{:?}", p.ok());
    }

    #[test]
    fn from_bytes_success_eth_hdr_size() {
        let _ = crate::layers::register_defaults();

        let p = Packet::from_bytes(&[0; 14], ENCAP_TYPE_ETH);

        assert!(p.is_ok(), "{:?}", p.err());
    }

    #[test]
    fn parse_valid_ipv4_packet() {
        let _ = layers::register_defaults();

        let array = hex::decode("00e08100b02800096b88f5c90800450000c1d24940008006c85b0a000005cf2e865e0cc30050a80076877de014025018faf0ad62000048454144202f76342f69756964656e742e6361623f3033303730313132303820485454502f312e310d0a4163636570743a202a2f2a0d0a557365722d4167656e743a20496e6475737472792055706461746520436f6e74726f6c0d0a486f73743a2077696e646f77737570646174652e6d6963726f736f66742e636f6d0d0a436f6e6e656374696f6e3a204b6565702d416c6976650d0a0d0a");
        assert!(array.is_ok());

        let array = array.unwrap();
        let len = array.len();
        let p = Packet::from_bytes(&array, ENCAP_TYPE_ETH);
        assert!(p.is_ok(), "{:?}", p.err());

        let p = p.unwrap();
        assert!(p.layers.len() == 3, "{:?}", p);
        assert!(
            p.unprocessed.len() == (len - (ETH_HEADER_LEN + IPV4_BASE_HDR_LEN + TCP_BASE_HDR_LEN)),
            "{}:{}:{:#?}",
            len,
            p.unprocessed.len(),
            p
        );
    }

    #[test]
    fn parse_valid_ipv6_packet() {
        let _ = layers::register_defaults();

        let array = hex::decode("000573a007d168a3c4f949f686dd600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402");
        assert!(array.is_ok());

        let array = array.unwrap();
        let len = array.len();
        let p = Packet::from_bytes(&array, ENCAP_TYPE_ETH);
        assert!(p.is_ok(), "{:?}", p.err());

        let p = p.unwrap();
        assert!(p.layers.len() == 3, "{:?}", p);
        assert!(
            p.unprocessed.len() == (len - (ETH_HEADER_LEN + IPV6_BASE_HDR_LEN + TCP_BASE_HDR_LEN)),
            "{}:{}:{:#?}",
            len,
            p.unprocessed.len(),
            p
        );
    }

    #[test]
    fn parse_valid_dns_packet() {
        use crate::layers;

        let _ = layers::register_defaults();

        let dns_query = vec![
            0xfe, 0x54, 0x00, 0x3e, 0x00, 0x96, 0x52, 0x54, /* .T.>..RT */
            0x00, 0xbd, 0x1c, 0x70, 0x08, 0x00, 0x45, 0x00, /* ...p..E. */
            0x00, 0x3c, 0x22, 0xe0, 0x00, 0x00, 0x40, 0x11, /* .<"...@. */
            0xe2, 0x38, 0xc0, 0xa8, 0x7a, 0x46, 0xc0, 0xa8, /* .8..zF.. */
            0x7a, 0x01, 0xc3, 0x35, 0x00, 0x35, 0x00, 0x28, /* z..5.5.( */
            0x75, 0xd2, 0x52, 0x41, 0x01, 0x00, 0x00, 0x01, /* u.RA.... */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* ww.googl */
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, /* e.com... */
            0x00, 0x01, /* .. */
        ];

        let p = Packet::from_bytes(&dns_query, ENCAP_TYPE_ETH);
        assert!(p.is_ok(), "{:?}", p.err());
        let p = p.unwrap();
        assert!(p.layers.len() == 4, "{:?}", p);
    }
}
