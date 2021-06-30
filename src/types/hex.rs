//! A collection of types suitable for Hex output
//!
//! When displaying certain data, it's useful to be able to display that data as Hex as opposed to
//! normal integer display. The types in this module are just new type structs that wrap the
//! individual u8/u16/u32/u64 types and implement their own `Display`/`Debug` traits.
//!

macro_rules! generate_serialize_hex_fns {
    (($fn:ident, $format:literal, $trait:path)) => {
        pub fn $fn<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
            T: $trait,
        {
            serializer.serialize_str(format!($format, value).as_str())
        }
    };

    ($($tt:tt,)*) => {
        $(
            generate_serialize_hex_fns!($tt);
        )+
    };
}

// Generate functions that can be used to Serialize a value to Hex
generate_serialize_hex_fns! {
    (serialize_lower_hex_u8, "0x{:02x}", core::fmt::LowerHex),
    (serialize_lower_hex_u16, "0x{:04x}", core::fmt::LowerHex),
    (serialize_lower_hex_u32, "0x{:08x}", core::fmt::LowerHex),
    (serialize_lower_hex_u64, "0x{:016x}", core::fmt::LowerHex),
    (serialize_upper_hex_u8, "0x{:02X}", core::fmt::UpperHex),
    (serialize_upper_hex_u16, "0x{:04X}", core::fmt::UpperHex),
    (serialize_upper_hex_u32, "0x{:08X}", core::fmt::UpperHex),
    (serialize_upper_hex_u64, "0x{:016X}", core::fmt::UpperHex),
}
