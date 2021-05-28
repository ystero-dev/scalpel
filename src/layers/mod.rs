//! Scalpel Layers

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;

pub fn register_defaults() -> Result<(), crate::errors::Error> {
    ethernet::register_defaults()?;
    ipv4::register_defaults()?;
    ipv6::register_defaults()?;

    Ok(())
}
