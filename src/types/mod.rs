//! All types that we are supporting

use crate::Layer;

mod macaddr;
pub use macaddr::*;

mod ethertype;
pub use ethertype::*;

mod ipaddr;
pub use ipaddr::*;

pub mod hex;

/// Creator function type
pub type LayerCreatorFn = fn() -> Box<dyn Layer>;

/// Packet Encapsulation Type
///
/// This value is same as those supported by [libpcap][libpcap]
///
/// [libpcap]: https://www.tcpdump.org/
pub type EncapType = u8;

pub static ENCAP_TYPE_ETH: EncapType = 1_u8;
