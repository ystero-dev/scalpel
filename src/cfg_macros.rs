#![allow(unused_macros)]

macro_rules! cfg_python {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "python-bindings")]
            $item
        )*
    }
}

macro_rules! cfg_wasm {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "wasm")]
            $item
        )*
    }
}

macro_rules! wasm_tests {

    ( $( #[test] $($item:item)?)*) => {
        $(
            #[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
            #[test]
            $($item)?
        )*
    };

}
