//! A simple example demonstrating how to dump a packet as a Json
//!

use scalpel;

fn main() {
    let _ = scalpel::register_defaults();
    let ipv6_packet = hex::decode("000573a007d168a3c4f949f686dd600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402").unwrap();
    let p = scalpel::Packet::from_u8(&ipv6_packet, scalpel::ENCAP_TYPE_ETH);

    println!("{}", serde_json::to_string_pretty(&p.unwrap()).unwrap());
}
