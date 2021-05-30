use scalpel::IPv6Address;
use std::net::Ipv6Addr;
use std::time::Instant;

use core::convert::TryInto;
use core::fmt::Write;

const N: u32 = 1_000_000;
fn main() {
    let ipv6_addr = "2a03:2880:f12f:183:face:b00c:0:25de"
        .parse::<Ipv6Addr>()
        .unwrap();
    let ipv6_address: IPv6Address = ipv6_addr.segments()[..].try_into().unwrap();

    // Run for our IPv6Addres
    for run in 1..10 {
        let t = Instant::now();

        for _ in 1..N {
            let mut w = String::new();

            let _ = write!(w, "{}", ipv6_address);
        }
        let took = t.elapsed();
        println!(
            "Run{}:IPV6Address: {} Iterations took {} us.",
            run,
            N,
            took.as_secs_f64() * 1000000.0
        );
    }

    // Run for std::net's IPv6Address
    for run in 1..10 {
        let t = Instant::now();

        for _ in 1..N {
            let mut w = String::new();

            let _ = write!(w, "{}", ipv6_addr);
        }
        let took = t.elapsed();
        println!(
            "Run{}:std::net::Ipv6Addr: {} Iterations took {} us.",
            run,
            N,
            took.as_secs_f64() * 1000000.0
        );
    }
}
