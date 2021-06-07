///! EtherType structure and definition of Well Known EtherTypes
///
use core::fmt;

use std::hash::Hash;

use serde::Serialize;

#[derive(PartialEq, Clone, Default, Hash, Eq, Serialize)]
pub struct EtherType(pub u16);

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04X}", self.0)
    }
}

impl fmt::Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub static ETHERTYPE_IP: EtherType = EtherType(0x0800_u16);
pub static ETHERTYPE_IP6: EtherType = EtherType(0x86dd_u16);
