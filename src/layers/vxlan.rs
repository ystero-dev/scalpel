//! VXLAN layer
use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::Layer;

use crate::layers::{ethernet, udp};

/// VXLAN header length
pub const VXLAN_HEADER_LENGTH: usize = 8_usize;

/// IANA Assigned port number for VXLAN
pub const VXLAN_PORT: u16 = 4789;

// Register ourselves with UDP
pub(crate) fn register_defaults() -> Result<(), Error> {
    udp::register_app(VXLAN_PORT, VXLAN::creator)?;

    Ok(())
}

/// Structure representing VXLAN Header
#[derive(Debug, Default, Serialize)]
pub struct VXLAN {
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    flags: u8,
    // FIXME: is actually only 24 bits(3 bytes)
    vni: u32,
}

impl VXLAN {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::<VXLAN>::default()
    }
}

impl Layer for VXLAN {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < VXLAN_HEADER_LENGTH {
            return Err(Error::TooShort {
                required: VXLAN_HEADER_LENGTH,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }
        self.flags = u8::from_be(bytes[0]);
        self.vni = ((u16::from_be_bytes(bytes[4..6].try_into().unwrap()) as u32) << 8)
            | (u8::from_be(bytes[6]) as u32);

        Ok((Some(ethernet::Ethernet::creator()), VXLAN_HEADER_LENGTH))
    }

    fn name(&self) -> &'static str {
        "VXLAN"
    }

    fn short_name(&self) -> &'static str {
        "vxlan"
    }
}

#[cfg(test)]
mod tests {
    use crate as scalpel;

    use scalpel::layers;

    wasm_tests! {
        #[test]
        fn parse_valid_vxlan_packet() {
            let _ = layers::register_defaults();

            let vxlan_packet = hex::decode("00005e00531100005e005303080045000096002c4000fd1177250202020201010101504f12b500820000080000000013940000005e00536500005e00536608004500006400280000ff012155c0a80c66c0a80c6500005c27000c000000000000007c299babcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
                                            .unwrap();

            let p = scalpel::Packet::from_bytes(&vxlan_packet, scalpel::ENCAP_TYPE_ETH);
            assert!(p.is_ok());

            let p = p.unwrap();

            let layer_type_names = [
                "Ethernet", "IPv4", "UDP", "VXLAN", "Ethernet",
                "IPv4",
                // TODO: Uncomment when ICMP gets supported
                // "ICMP",
            ];
            p.layers
                .iter()
                .map(|layer| layer.name())
                .zip(layer_type_names)
                .for_each(|(layer_name, type_name)| {
                    assert_eq!(layer_name, type_name, "{}", layer_name);
                });
        }
    }
}
