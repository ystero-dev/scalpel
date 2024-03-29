use std::error::Error;

use scalpel::{layers, ENCAP_TYPE_ETH};

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
        .fold(String::new(), |acc, num| {
            acc + "0x" + &num.to_string() + " "
        })
        .trim_end()
        .to_string();

    println!("res: {:#?}", res_string);

    let p = scalpel::Packet::from_bytes(&result[0], ENCAP_TYPE_ETH);
    println!("{}", serde_json::to_string_pretty(&p.unwrap()).unwrap());

    Ok(())
}
