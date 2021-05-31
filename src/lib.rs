//! A crate for dissecting and sculpting Network packets.
//!
//! Being able to dissect a stream of bytes from wire into a human or machine readable structures
//! can be useful in many applications. `scalpel` is designed for such use cases. The functionality
//! of scalpel is designed for use-cases that are targetted by [gopacket][go-packet] or
//! [Wireshark][ws].
//!
//! [go-packet]: https://github.com/google/gopacket/
//! [ws]: https://wireshark.org
//!
//! The main focus of `scalpel` is to provide API based framework for dissecting packets such that
//! it's possible for anyone to write a dissector for a new protocol. `scalpel` natively supports
//! dissection for a set of widely used protocols out of the box. See [`layers`] for details.
//!
//! A Basic unit in a scalpel is a [`Packet`], a struct representing a dissected Packet from the
//! wire, which is made up of a set of one or more `layers`. See [`crate::Packet`] for details.

pub mod layers;
pub use layers::register_defaults;

mod errors;
pub use errors::*;

mod packet;
pub use packet::*;

mod layer;
pub use layer::*;

mod types;
pub use types::*;
