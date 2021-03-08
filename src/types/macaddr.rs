//! Handling of MAC Address Type
//!

#[derive(Debug, Default, Clone)]
pub struct MACAddress([u8; 6]);

impl From<&'_ [u8]> for MACAddress {
    fn from(slice: &[u8]) -> Self {
        let mut m = MACAddress::default();
        m.0.copy_from_slice(slice);
        m
    }
}
