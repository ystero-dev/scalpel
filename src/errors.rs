//! Error types for scalpel.

/// Error type for [`scalpel`][`crate`]
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Byte Array too short
    TooShort {
        required: usize,
        available: usize,
        data: String,
    },

    /// A generic parsing error.
    ParseError(String),

    /// A layer registration error.
    RegisterError(String),

    /// Error in sculpting
    SculptingError(String),
}

// FIXME: Should work with `no_std`
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}

// Python Bindings
#[cfg(all(feature = "python-bindings", not(target_family = "wasm")))]
impl std::convert::From<Error> for pyo3::PyErr {
    // TODO: Add proper error reporting
    fn from(_e: Error) -> pyo3::PyErr {
        pyo3::exceptions::PyValueError::new_err("Error")
    }
}
