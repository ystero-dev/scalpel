//! Scalpel Layers

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;

pub mod udp;

pub mod dns;

include!(concat!(env!("OUT_DIR"), "/register_defaults.rs"));
