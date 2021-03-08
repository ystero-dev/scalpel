//! Scalpel: A crate for dissecting and sculpting Packets.
//!
//! A Basic unit in a scalpel is a `Packet`, a struct representing a Packet captured (and
//! dissected) from the wire.
//!
//! A packet is a collection of `Layer`s. Each `Layer` is a struct implementing the `Layer` trait

mod ethernet;

mod errors;
pub use errors::*;

mod packet;
pub use packet::*;

mod layer;
pub use layer::*;

mod types;
pub use types::*;
