//! Error types

/// Error type for [`scalpel`][`crate`]
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Byte Array too short
    TooShort,
    /// A generic arsing error.
    ParseError,
    /// A layer registration error.
    RegisterError,
}

// FIXME: Should work with `no_std`
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}
