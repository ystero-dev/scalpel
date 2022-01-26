//! Error types for scalpel.

/// Error type for [`scalpel`][`crate`]
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Byte Array too short
    TooShort,
    /// A generic parsing error.
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

// Python Bindings
impl std::convert::From<Error> for pyo3::PyErr {
    // TODO: Add proper error reporting
    fn from(_e: Error) -> pyo3::PyErr {
        pyo3::exceptions::PyValueError::new_err("Error")
    }
}
