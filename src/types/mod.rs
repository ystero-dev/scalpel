//! All types that we are supporting

use crate::layer::Layer;

mod macaddr;
pub use macaddr::*;

mod ethertype;
pub use ethertype::*;

mod ipaddr;
pub use ipaddr::*;

pub mod hex;

/// Type for a 'Layer' creator function.
pub type LayerCreatorFn = fn() -> Box<dyn Layer + Send>;

/// Packet Encapsulation Type
///
/// This value is same as those supported by [libpcap][libpcap]
///
/// [libpcap]: https://www.tcpdump.org/
pub type EncapType = u16;

pub static ENCAP_TYPE_ETH: EncapType = 1;

pub static ENCAP_TYPE_LINUX_SLL: EncapType = 113;

pub static ENCAP_TYPE_LINUX_SLL2: EncapType = 276;
