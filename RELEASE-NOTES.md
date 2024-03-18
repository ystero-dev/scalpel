# Releases

## Release 0.4.0

### Features

1. Support for ICMP and ICMPv6
2. Support for IP Options - `EOOL`, `NOP`, `RR`, `MTUP`, `MTUR`
3. Removed dependency on `lazy_static` and started using `OnceLock`.

### Bug Fixes

1. Issues with parsing `SOA` RRs in `DNS`.
2. Incorrect dissection of Ethernet Source and Destination.
3. `build.rs` fixes for working on Windows.


### Contributors

- Mohammad Aadil Shabier (@aadilshabier)
- Chinmaya Sahoo (@csking101)
- Harshit Gupta (@hgupta12)
- JnanaN (@JnanaN)
- Abhijit Gadgil (@gabhijit)


## Release 0.3.1

### Features

1. Support for `MPLS` and `VxLAN`


### Bug Fixes

1. Correctly handling `num_packets` in the examples.
2. Consistent use of the constants `*_HEADER_LENGTH`
3. Improved formatting of the `register_defaults` function as a single string.

### Contributors

- Mohammad Aadil Shabier (@aadilshabier)
- Chinmaya Sahoo (@csking101)
- Abhijit Gadgil (@gabhijit)


## Release 0.3.0

### Features

1. Optional `logging` feature for the crate.
2. Support for Linux `SLL` `v1` and `v2` encapsulation.
3. Improved `TooShort` error for better debugging
4. Examples: Support for PCAP capture on `any` device.

### Bug Fixes

1. Fixed an issue with `register_encap_type`.


### Contributors

- Abhijit Gadgil (@gabhijit)

