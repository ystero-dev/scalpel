//! Definition of IP Address Types
//!
//! This module defines types for IPv4 and IPv6 which are simply based on the u8 arrays.

use core::convert::{TryFrom, TryInto};
use core::fmt;

use crate::errors::Error as CrateError;

#[derive(Default, Clone)]
pub struct IPv4Address([u8; 4]);

impl TryFrom<&'_ [u8]> for IPv4Address {
    type Error = CrateError;

    fn try_from(slice: &'_ [u8]) -> Result<Self, Self::Error> {
        if slice.len() != 4 {
            Err(CrateError::ParseError)
        } else {
            let mut ip = IPv4Address::default();
            ip.0.copy_from_slice(slice);
            Ok(ip)
        }
    }
}

impl TryFrom<&'_ str> for IPv4Address {
    type Error = CrateError;

    fn try_from(slice: &'_ str) -> Result<Self, Self::Error> {
        Err(CrateError::ParseError)
    }
}

impl fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Debug for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Default, Clone)]
pub struct IPv6Address([u16; 8]);

impl TryFrom<&'_ [u8]> for IPv6Address {
    type Error = CrateError;

    fn try_from(slice: &'_ [u8]) -> Result<Self, Self::Error> {
        if slice.len() != 16 {
            Err(CrateError::ParseError)
        } else {
            let array: [u8; 16] = slice.try_into().unwrap();
            // FIXME: Check whether be16::from_bytes is faster than this?
            //
            unsafe {
                let ip: IPv6Address = core::mem::transmute_copy(&array);
                Ok(ip)
            }
        }
    }
}

impl TryFrom<&'_ str> for IPv6Address {
    type Error = CrateError;

    fn try_from(slice: &'_ str) -> Result<Self, Self::Error> {
        Err(CrateError::ParseError)
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // FIXME: Also implement short hand notation
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl fmt::Debug for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
