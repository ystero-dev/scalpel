//! Scalpel Layers

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod linux_sll;
pub mod linux_sll2;

pub mod tcp;
pub mod udp;

pub mod dns;

pub mod arp;

pub mod sctp;

pub mod m3ua;

<<<<<<< HEAD
pub mod vxlan;
=======
pub mod mpls;
>>>>>>> c9d5509 (Implemented the MPLS protocol)

include!(concat!(env!("OUT_DIR"), "/register_defaults.rs"));
