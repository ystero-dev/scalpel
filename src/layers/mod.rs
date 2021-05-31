//! Scalpel Layers

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;

/// Register Default protocol handlers.
///
/// Each [`crate::layer::Layer`] in `scalpel` will be decoded by a certain field in the upper
/// layer for which this particular layer is a payload. For example, [`ipv4::IPv4`] is a payload
/// for [`ethernet::Ethernet`]. Thus while decoding a particular layer, the next layer to be
/// decoded is determined by a value of certain filed in the current layer. In the example above,
/// EtherType in the Ethernet header determines the next layer (EtherType: 0x8000 corresponds to
/// [`ipv4::IPv4`]).
///
/// In this function we just call the `register_defaults` layers  for the currently supported
/// layers.
///
/// When a new layer is defined outside the crate, that particular layer may use a `register_*`
/// function in it's upper layer to request it's dissection. This glues all the dissectors for the
/// layers together.
pub fn register_defaults() -> Result<(), crate::errors::Error> {
    ethernet::register_defaults()?;
    ipv4::register_defaults()?;
    ipv6::register_defaults()?;

    Ok(())
}
