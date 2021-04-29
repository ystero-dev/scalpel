//! All types that we are supporting

use crate::Layer;

mod macaddr;
pub use macaddr::*;

/// Creator function type
pub type LayerCreatorFn = fn() -> Box<dyn Layer>;

// FIXME: At some time, let them make consistent with `libpcap`.
pub type EncapType = u8;

pub static ENCAP_TYPE_ETH: EncapType = 1_u8;
