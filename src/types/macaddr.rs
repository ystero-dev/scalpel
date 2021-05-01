//! MAC Address Type
//!
//! A Type representing MAC Address as an array of `[u8; 6]`
//!

use std::convert::TryFrom;

use crate::errors::Error as CrateError;

#[derive(Debug, Default, Clone)]
pub struct MACAddress([u8; 6]);

impl TryFrom<&'_ [u8]> for MACAddress {
    type Error = CrateError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != 6 {
            Err(CrateError::ParseError)
        } else {
            let mut m = MACAddress::default();
            m.0.copy_from_slice(slice);
            Ok(m)
        }
    }
}

impl TryFrom<&'_ str> for MACAddress {
    type Error = CrateError;

    fn try_from(_str: &str) -> Result<Self, Self::Error> {
        Err(CrateError::ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error as CrateError;
    use std::convert::TryInto;

    #[test]
    fn byte_array_too_small_fail() {
        let mac_address: Result<MACAddress, _> = [00u8, 01u8, 02u8][..].try_into();
        assert!(mac_address.is_err());
        assert!(mac_address.err().unwrap() == CrateError::ParseError);
    }

    #[test]
    fn byte_array_too_large_fail() {
        let mac_address: Result<MACAddress, _> = [00u8; 10].as_ref().try_into();
        assert!(mac_address.is_err());
        assert!(mac_address.err().unwrap() == CrateError::ParseError);
    }

    #[test]
    fn str_always_fail() {
        let mac_address: Result<MACAddress, _> = "".try_into();
        assert!(mac_address.is_err());
        assert!(mac_address.err().unwrap() == CrateError::ParseError);
    }
}
