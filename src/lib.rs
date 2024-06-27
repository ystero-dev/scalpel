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
//! - `logging`: Enable logging during decoding the packets. Since, packet dissection is usually
//!              done in the fast, path, use this feature mainly for debugging packet dissections.
//!              an error log is provided for the failing `register_defaults` function when this
//!              feature is enabled.
//! - `wasm`: Build WASM capability in the scalpel. Currently `dissect_packet` API is provided,
//!           dissects the packet and a JSON is generated for the packet.
//! - `sculpting`: Experimental, allows one to generate packet from layers using metadata. For
//!                example this will be useful to develop packet generators.
//!
//! Note: `wasm` and `python-bindings` features cannot be enabled at the same time.

#[cfg(all(feature = "python-bindings", feature = "wasm"))]
compile_error!(
    "feature \"python-bindings\" and feature \"wasm\" cannot be enabled at the same time"
);

#[cfg(all(target_family = "wasm", not(feature = "wasm")))]
compile_error!("feature \"wasm\" is required for \"wasm32\" targets.");

#[cfg(all(not(target_family = "wasm"), feature = "wasm"))]
compile_error!("feature \"wasm\" is only supported for \"wasm32\" targets.");

#[cfg(all(target_family = "wasm", feature = "python-bindings"))]
compile_error!("feature \"python-bindings\" is not supported for \"wasm32\" targets.");

#[macro_use]
pub mod cfg_macros;

pub mod layers;

pub mod errors;

pub mod packet;

pub mod layer;

pub mod types;

pub mod builder;

#[doc(inline)]
pub use layers::register_defaults;

#[doc(inline)]
pub use layer::Layer;

#[doc(inline)]
pub use packet::Packet;

#[doc(inline)]
pub use types::{ENCAP_TYPE_ETH, ENCAP_TYPE_LINUX_SLL, ENCAP_TYPE_LINUX_SLL2};

cfg_python! {
    use pyo3::prelude::*;

    /// Python bindings for packet dissection and sculpting in Rust (scalpel)
    #[pymodule]
    fn scalpel(py: Python, m: &PyModule) -> PyResult<()> {
        packet::register(py, m)?;
        Ok(())
    }
}

cfg_wasm! {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn dissect_packet(packet: String) -> String {
        let _ = layers::register_defaults();

        let packet = hex::decode(packet);

        let packet = packet.unwrap();

        let p = Packet::from_bytes(&packet, ENCAP_TYPE_ETH);

        let p = p.unwrap();

        serde_json::to_string_pretty(&p).unwrap()
    }
}
