//! 'Layer' trait
//!
//! [`Layer`] trait is central to [`scalpel`][`crate`]. All the dissectors for individual protocols
//! implement the `Layer` trait. Each Layer will implement a `from_u8` function that will return
//! the result of parsing the given byte slice.

use core::fmt::Debug;

use erased_serde::serialize_trait_object;

use crate::Error;

pub trait Layer: Debug + erased_serde::Serialize {
    /// Basic 'decoder' function.
    ///
    /// The return value is a Tuple (`Option<Box<dyn Error>>`, usize)` on success. This indicates
    /// the decoded Struct wrapped as a Layer and the number of bytes consumed. Typically returns
    /// a [ParseError][`crate::errors::Error::ParseError`], but may as well return other values.
    /// When No further decoding is possible, this function should return a `None` along with the
    /// number of bytes consumed by the 'decoder' function. A return value of `None` indicates,
    /// we do not know how to decode further, but this is not an error. This might happen for
    /// example for protocols that are not yet supported.
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error>;

    /// Name for the given layer.
    fn name(&self) -> &str;

    /// Short name for the given layer.
    fn short_name(&self) -> &str;
}

serialize_trait_object!(Layer);

///
/// An empty Layer indicating 'last' decoded layer.
///
/// Typically when a Layer can no longer determine the next layer to be decoded, the 'decoder'
/// function returns `None` (See `from_u8`). This is used for adding an 'Empty' layer as next layer
/// which is discarded.
#[derive(Debug, Default, serde::Serialize)]
pub struct EmptyLayer;

impl Layer for EmptyLayer {
    fn from_u8(&mut self, _btes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        Ok((Some(Box::new(EmptyLayer {})), 0))
    }

    #[inline(always)]
    fn name(&self) -> &str {
        "empty"
    }

    #[inline(always)]
    fn short_name(&self) -> &str {
        "empty"
    }
}
