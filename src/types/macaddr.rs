//! MAC Address Type
//!
//! A Type representing MAC Address as an array of `[u8; 6]`
//!

use core::convert::TryFrom;
use core::fmt;

use serde::{Serialize, Serializer};

use crate::errors::Error as CrateError;

#[derive(Default, Clone)]
pub struct MACAddress([u8; 6]);

impl MACAddress {
    /// Returns a slice containing the entire inner array.
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable slice containing the entire inner array.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Serialize for MACAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

impl From<[u8; 6]> for MACAddress {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl TryFrom<&'_ [u8]> for MACAddress {
    type Error = CrateError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != 6 {
            Err(CrateError::ParseError(format!(
                "MacAddress: {}",
                hex::encode(slice)
            )))
        } else {
            let mut m = MACAddress::default();
            m.0.copy_from_slice(slice);
            Ok(m)
        }
    }
}

impl TryFrom<&'_ str> for MACAddress {
    type Error = CrateError;

    fn try_from(str: &str) -> Result<Self, Self::Error> {
        Err(CrateError::ParseError(format!("MacAddress: {}", str)))
    }
}

impl fmt::Display for MACAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MACAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error as CrateError;
    use core::convert::TryInto;

    #[test]
    fn byte_array_too_small_fail() {
        let mac_address: Result<MACAddress, _> = [00u8, 01u8, 02u8][..].try_into();
        assert!(mac_address.is_err());
        assert!(
            mac_address.err().unwrap() == CrateError::ParseError("MacAddress: 000102".to_string())
        );
    }

    #[test]
    fn byte_array_too_large_fail() {
        let mac_address: Result<MACAddress, _> = [00u8; 10].as_ref().try_into();
        assert!(mac_address.is_err());
        assert!(
            mac_address.err().unwrap()
                == CrateError::ParseError("MacAddress: 00000000000000000000".to_string())
        );
    }

    #[test]
    fn str_always_fail() {
        let mac_address: Result<MACAddress, _> = "".try_into();
        assert!(mac_address.is_err());
        assert!(mac_address.err().unwrap() == CrateError::ParseError("MacAddress: ".to_string()));
    }
}
