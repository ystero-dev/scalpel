//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use web_sys::console::error_1;
use web_sys::console::log_1;
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn simple_dissect_test() {
    let bytestream = "003096e6fc3900309605283888470001ddff45c0002800030000ff06a4e80a0102010a2200012af90017983210058dd58ea55010102099cd00000000";
    let encap_type = scalpel::ENCAP_TYPE_ETH;

    match scalpel::dissect_packet(encap_type, bytestream.to_string()) {
        Ok(result) => {
            log_1(&format!("Dissected packet result: {}", result).into());
        }
        Err(err) => {
            error_1(&format!("Dissect packet failed: {}", err).into());
            panic!("Dissect packet failed: {}", err);
        }
    }
    assert!(true);
}
