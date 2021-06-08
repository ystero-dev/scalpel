//! Definition of IP Address Types
//!
//! This module defines types for IPv4 and IPv6 which are simply based on the u8 arrays.

use core::convert::TryFrom;
use core::fmt;
use core::fmt::Write;

use serde::{Serialize, Serializer};

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

    fn try_from(_slice: &'_ str) -> Result<Self, Self::Error> {
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

impl Serialize for IPv4Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
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
            let mut ip = IPv6Address::default();
            for i in 0..8 {
                ip.0[i] = (slice[2 * i] as u16) << 8 | (slice[2 * i + 1] as u16);
            }
            Ok(ip)
        }
    }
}

impl TryFrom<&'_ [u16]> for IPv6Address {
    type Error = CrateError;

    fn try_from(slice: &'_ [u16]) -> Result<Self, Self::Error> {
        if slice.len() != 8 {
            Err(CrateError::ParseError)
        } else {
            let mut ip = IPv6Address::default();
            ip.0.copy_from_slice(slice);
            Ok(ip)
        }
    }
}

impl TryFrom<&'_ str> for IPv6Address {
    type Error = CrateError;

    fn try_from(_slice: &'_ str) -> Result<Self, Self::Error> {
        Err(CrateError::ParseError)
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Following structures are private structures used primarily by formatter.
        #[derive(Debug)]
        struct ZeroGroup {
            count: u8,
        }

        #[derive(Debug)]
        enum IPv6Segment {
            NonZeroSegment(u16),
            ZeroSegment(ZeroGroup),
        }

        #[derive(Debug, Default)]
        struct IPv6Segments([Option<IPv6Segment>; 8]);

        let mut segments = IPv6Segments::default();

        let mut in_zero_streak = true;
        let mut zero_streak_length = 0;

        // First Get the structure int Segments
        let mut i = 0;
        for entry in self.0.iter() {
            if entry == &0 {
                zero_streak_length += 1;
                in_zero_streak = true;
            } else {
                if in_zero_streak {
                    if zero_streak_length >= 1 {
                        let _ = segments.0[i].replace(IPv6Segment::ZeroSegment(ZeroGroup {
                            count: zero_streak_length,
                        }));
                        i += 1;
                    }
                }
                let _ = segments.0[i].replace(IPv6Segment::NonZeroSegment(*entry));
                i += 1;
                in_zero_streak = false;
                zero_streak_length = 0;
            }
        }
        if in_zero_streak {
            let _ = segments.0[i].replace(IPv6Segment::ZeroSegment(ZeroGroup {
                count: zero_streak_length,
            }));
        }

        // Output Segments
        let mut w = String::new();
        let mut long_zero_segments = 0;
        let mut zero_streak = false;
        for entry in segments.0.iter() {
            match *entry {
                Some(IPv6Segment::NonZeroSegment(ref num)) => {
                    zero_streak = false;
                    write!(&mut w, "{:x}", num)?;
                    write!(&mut w, ":")?;
                }
                Some(IPv6Segment::ZeroSegment(ref z)) => {
                    if z.count == 1 {
                        let _ = write!(&mut w, "0");
                    } else {
                        long_zero_segments += 1;
                        if long_zero_segments == 1 {
                            zero_streak = true;
                            let _ = w.pop();
                            write!(&mut w, ":")?;
                        } else {
                            for _ in 0..z.count {
                                write!(&mut w, "0:")?;
                            }
                            let _ = w.pop();
                        }
                    }
                    write!(&mut w, ":")?;
                }
                None => {}
            };
        }

        if !(long_zero_segments == 1 && zero_streak) {
            let _ = w.pop();
        }

        write!(f, "{}", w)
    }
}

impl fmt::Debug for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for IPv6Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

#[cfg(test)]
mod tests {

    use core::convert::TryInto;

    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ipv6_addr_tests() {
        struct IPv6AddressTestCase<'s> {
            input: &'s str,
            valid: bool,
        }

        let test_cases = vec![
            IPv6AddressTestCase {
                input: "fe80::1",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "::",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "::1",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "::ffff:0:0",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "::ffff:ff:ff",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "64:ff9b::",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "2a03:2880:f12f:183:face:b00c:0:25de",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "1:0:1:0:1:0:1:0",
                valid: true,
            },
            IPv6AddressTestCase {
                input: "2404:6800:4003:c04::1b",
                valid: true,
            },
        ];

        for test_case in test_cases {
            let ipv6: Result<IPv6Address, _> =
                test_case.input.parse::<Ipv6Addr>().unwrap().segments()[..].try_into();
            assert!(ipv6.is_ok(), test_case.valid);
            if test_case.valid {
                let ipv6 = ipv6.unwrap();
                assert_eq!(test_case.input, format!("{}", ipv6));
            }
        }
    }
}
