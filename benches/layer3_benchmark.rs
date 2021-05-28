use criterion::{criterion_group, criterion_main, Criterion};

use scalpel::register_defaults;
use scalpel::Packet;
use scalpel::ENCAP_TYPE_ETH;

pub fn new_ipv6_packet_from_u8(c: &mut Criterion) {
    let bytes = hex::decode("000573a007d168a3c4f949f686dd600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402").unwrap();
    let _ = register_defaults();
    c.bench_function("Parse_Ethernet_IPv6", |b| {
        b.iter(|| Packet::from_u8(&bytes, ENCAP_TYPE_ETH))
    });
}

pub fn new_ipv4_packet_from_u8(c: &mut Criterion) {
    let _ = register_defaults();

    let bytes = hex::decode("00e08100b02800096b88f5c90800450000c1d24940008006c85b0a000005cf2e865e0cc30050a80076877de014025018faf0ad62000048454144202f76342f69756964656e742e6361623f3033303730313132303820485454502f312e310d0a4163636570743a202a2f2a0d0a557365722d4167656e743a20496e6475737472792055706461746520436f6e74726f6c0d0a486f73743a2077696e646f77737570646174652e6d6963726f736f66742e636f6d0d0a436f6e6e656374696f6e3a204b6565702d416c6976650d0a0d0a").unwrap();

    c.bench_function("Parse_Ethernet_IPv4", |b| {
        b.iter(|| Packet::from_u8(&bytes, ENCAP_TYPE_ETH))
    });
}

criterion_group!(layer3, new_ipv6_packet_from_u8, new_ipv4_packet_from_u8);
criterion_main!(layer3);
