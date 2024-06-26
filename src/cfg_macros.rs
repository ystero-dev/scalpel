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
