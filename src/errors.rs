//! Error types

#[derive(Debug, PartialEq)]
pub enum Error {
    TooShort,
    ParseError,
    RegisterError,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}
