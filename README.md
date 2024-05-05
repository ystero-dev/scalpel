# Introduction

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/gabhijit/scalpel/CI.yml?branch=master)](https://github.com/gabhijit/scalpel/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/scalpel)](https://crates.io/crates/scalpel)
[![docs.rs](https://img.shields.io/docsrs/scalpel)](https://docs.rs/scalpel/latest/scalpel)

`scalpel` is a crate for Packet Dissection and Sculpting in Rust.

Scalpel can be used for dissecting packets on the wire and or generating packets from some specifications that can be sent on wire (This functionality is very early in development and a proof of concept implementation is available). Goal of 'scalpel' is to be able to be able to make packet dissection API friendly so that it's easier to use it in any application. See Examples in the `examples/` directory to get an idea of what kind of 'applications' it can be used in.

This is still early, actively being developed, the APIs are not stable and are likely to change substantially.

## Getting Started

Right now the supported API allows one to dissect packets on wire and display as Json (this uses `serde_json` and thus `serde`, so most `serde` format may work) -
1. `packet_json` - An example that demonstrates how any `buffer` can be read as a `scalpel::Packet` structure.
1. `pcap` - An example that demonstrates how to display packets in Json format those captured on the wire. (this should be run as `sudo`).

# Features

## Python Bindings

An experimental Python API is available to demonstrate how scalpel can be used for packet dissection from Python.  By default, python bindings are disabled. Python bindings can be enabled using `--features="python-bindings"` command line argument while building or running the code. Refer to ['Using Python Bindings'](https://github.com/gabhijit/scalpel/blob/master/using-python-bindings.md) to get started with using Python bindings. Currently, only we provide a basic dissection and displaying a packet as json functionality from the Python bindings. This support is a WIP.


## Wasm support

An experimental 'wasm' support is available. This support can be enabled using `--features=wasm`. Please note `python-bindings` and `wasm` are mutually exclusive features. [This repository](https://github.com/ystero-dev/scalpel-examples) contains an example using 'actix' based web server for running packet dissection inside the browser.

## Packet Generation (or Sculpting)

This is a WIP and a very early support. An initial implementation of creating a simple Ethernet and IP based packet and then serializing to wire is currently implemented. The goal of this feature is it should be possible to have an API friendly Packet Generator using `scalpel` crate.
