//! Error types

#[derive(Debug, PartialEq)]
pub enum Error {
    TooShort,
    ParseError,
    RegisterError,
}

// FIXME: Should work with `no_std`
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}
