//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn simple_dissect_test() {
    let bytestream = "003096e6fc3900309605283888470001ddff45c0002800030000ff06a4e80a0102010a2200012af90017983210058dd58ea55010102099cd00000000";
    scalpel::dissect_packet(bytestream.to_string());
    assert!(true);
}
