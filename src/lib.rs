//! A crate for dissecting and sculpting network packets.
//!
//! Being able to dissect a stream of bytes from wire into a human or machine readable structures
//! can be useful in many applications. `scalpel` is designed for such use cases. In other
//! languages such use-cases are served by tools like [gopacket][go-packet] or
//! [Wireshark][ws].
//!
//! [go-packet]: https://github.com/google/gopacket/
//! [ws]: https://wireshark.org
//!
//! Ability to dissect packets and looking at details of each of the protocols carried in the
//! Packet can be quite useful for debugging protocol implementations, network issuess and so on.
//! Also, having such ability in an API friendly way should allow -
//! - Writing dissector for new protocols.
//! - Using the dissection functionality in your own application.
//!
//! Thus, the main focus of `scalpel` is to provide API based framework for dissecting packets such
//! that it's possible for anyone to write a dissector for a new protocol. `scalpel` natively
//! supports dissection for a set of widely used protocols out of the box. See [`layers`] modules
//! for supported protocols.
//!
//! A Basic unit in a scalpel is a [`Packet`][`crate::Packet`] structure that represents a
//! dissected Packet from the wire. This structure carries information about the dissected
//! protocols, each of the protocol that is dissected implements a trait called
//! [`Layer`][`crate::Layer`]. See [`Packet`][`crate::Packet`] for details.
//!
//! ## Opt-in Features
//! - `python-bindings`: Python bindings for the scalpel Rust API. Currently support is to
//!                      generate [`Packet`] structure in Python.

pub mod layers;

pub mod errors;

pub mod packet;

pub mod layer;

pub mod types;

#[doc(inline)]
pub use layers::register_defaults;

#[doc(inline)]
pub use layer::Layer;

#[doc(inline)]
pub use packet::Packet;

#[doc(inline)]
pub use types::ENCAP_TYPE_ETH;

#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;

/// Python bindings for packet dissection and sculpting in Rust (scalpel)
#[cfg(feature = "python-bindings")]
#[pymodule]
fn scalpel(py: Python, m: &PyModule) -> PyResult<()> {
    packet::register(py, m)?;
    Ok(())
}
