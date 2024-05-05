#![allow(unused)]
use std::error::Error;

use scalpel::{layers, ENCAP_TYPE_ETH};

#[cfg(feature = "sculpting")]
fn main() -> Result<(), Box<dyn Error>> {
    let _ = scalpel::register_defaults()?;

    let eth_layer = Box::new(layers::ethernet::Ethernet::new());
    let ipv4_layer = Box::new(layers::ipv4::IPv4::new());
    let bytes = [0x12, 0x34, 0x56, 0x78, 0x90];

    let builder = scalpel::builder::PacketBuilder::new()
        .stack(eth_layer)?
        .stack(ipv4_layer)?
        .stack_bytes(&bytes);

    let (_, result) = builder.build().unwrap();

    let res_string = result[0]
        .iter()
        .map(|num| format!("{:02x}", num))
        .collect::<Vec<_>>()
        .join("");

    println!("Packet Data: {:#?}", res_string);

    let p = scalpel::Packet::from_bytes(&result[0], ENCAP_TYPE_ETH);
    println!("{}", serde_json::to_string_pretty(&p.unwrap()).unwrap());

    Ok(())
}

#[cfg(not(feature = "sculpting"))]
fn main() {
    eprintln!("Feature 'sculpting' is required for this example!.");
}
