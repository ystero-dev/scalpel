# Scalpel

Packet Dissection and Sculpting in Rust

Scalpel can be used for Dissecting packets on the wire and or generating packets from some specifications that can be sent on wire (This functionality is not being implemented at present). Goal of 'scalpel' is to be able to be able to make packet dissection easy as well as in an API friendly way so that it's easier to use it in any applications. See Examples in the `examples/` directory to get an idea of what kind of 'applications' it can be used in.

This is still early, actively being developed, the APIs are not stable and are likely to change substantially.

## Getting Started

You can run the example in the `examples` directory as `cargo run --example packet_to_json` which should display the dissected packet in the Json format.
