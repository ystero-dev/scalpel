//"003096e6fc3900309605283888470001ddff45c0002800030000ff06a4e80a0102010a2200012af90017983210058dd58ea55010102099cd00000000"

// "mpls": {
//     "label": 29,
//     "exp": "0x06",
//     "bos": "0x01",
//     "ttl": "0xff"
// }

use scalpel;

fn main() {
    let _ = scalpel::register_defaults();

    let mpls_packet = hex::decode("003096e6fc3900309605283888470001ddff45c0002800030000ff06a4e80a0102010a2200012af90017983210058dd58ea55010102099cd00000000");
    let mpls_packet = mpls_packet.unwrap();
    let p = scalpel::Packet::from_bytes(&mpls_packet, scalpel::ENCAP_TYPE_ETH);

    println!("{}", serde_json::to_string_pretty(&p.unwrap()).unwrap());
}
