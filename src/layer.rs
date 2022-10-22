//! 'Layer' trait
//!
//! [`Layer`] trait is central to [`scalpel`][`crate`]. All the dissectors for individual protocols
//! implement the `Layer` trait. Each Layer will implement a `decode_bytes` function that will return
//! the result of parsing the given byte slice.

use core::fmt::Debug;

use erased_serde::serialize_trait_object;

use crate::errors::Error;

/// `Layer` Trait defines a 'Layer' in a Packet
///
/// Typically a Layer will correspond to Data Link Layer, Network Layer, Transport Layer or the
/// Application Layer. Each of the supported 'protocols' have implementation for this trait.
pub trait Layer: Send + Debug + erased_serde::Serialize {
    /// Main 'decoder' function.
    ///
    /// The return value is a Tuple `(Option<Box<dyn Layer + Send>>, usize)` on success. This indicates
    /// the decoded Struct wrapped as a Layer and the number of bytes consumed. Typically returns
    /// a [ParseError][`crate::errors::Error::ParseError`], but may as well return other values.
    /// When No further decoding is possible, this function should return a `None` along with the
    /// number of bytes consumed by the 'decoder' function. A return value of `None` indicates,
    /// we do not know how to decode further, but this is not an error. This might happen for
    /// example for protocols that are not yet supported. Additional `Send` trait is required for
    /// Python bindings.
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error>;

    /// Name for the given layer.
    fn name(&self) -> &'static str;

    /// Short name for the given layer.
    fn short_name(&self) -> &'static str;
}

serialize_trait_object!(Layer);
