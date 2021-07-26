//! Scalpel Layers

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;

pub mod tcp;
pub mod udp;

pub mod dns;

pub mod arp;

pub mod sctp;

include!(concat!(env!("OUT_DIR"), "/register_defaults.rs"));
