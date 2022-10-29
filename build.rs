use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

// This generates the `layers::register_defaults` function. Right now the implementation is rather
// dirty and perhaps can be made better using APIs from `ra_ap_hir` or `ra_ap_vfs`, but that's an
// overkill at the moment. We should fix bugs in this if any.
fn main() -> std::io::Result<()> {
    let sources_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join("layers");

    let walker = walkdir::WalkDir::new(&sources_dir);

    let mut reg_defaults = Vec::new();
    for entry in walker {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            eprintln!("Path: {:#?}", entry.path());
            let mut file = File::open(entry.path()).unwrap();
            let mut content = String::new();
            file.read_to_string(&mut content).unwrap();

            let ast = syn::parse_file(&content).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("file: {:?}, Error: {:?}", entry.path(), e),
                )
            })?;
            for item in ast.items {
                if let syn::Item::Fn(ref i) = item {
                    // The AST contains a Function with `register_defaults` as identifer.
                    // Collect it to be written to final `layers::register_defaults`.
                    if i.sig.ident == "register_defaults" {
                        let mut register_defaults_fn_path = entry
                            .path()
                            .strip_prefix(&sources_dir)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string()
                            .replace('/', "::")
                            .replace("mod.rs", "")
                            .replace(".rs", "::");

                        register_defaults_fn_path.push_str("register_defaults()?;");
                        reg_defaults.push(register_defaults_fn_path);
                    }
                }
            }
        }
    }

    let mut output_str = String::new();
    output_str += "use std::sync::Once;";
    output_str += "static INIT: Once = Once::new();";
    output_str += r#"
/// Register Default protocol handlers.
///
/// Each [`Layer`][`crate::layer::Layer`] in `scalpel` will be decoded by a certain field in the
/// lower layer for which this particular layer is a payload. For example, [`ipv4::IPv4`] is a
/// payload for [`ethernet::Ethernet`]. Thus while decoding a particular layer, the next layer to
/// be decoded is determined by a value of certain field in the current layer. In the example
/// above, EtherType in the Ethernet header determines the next layer (EtherType: 0x8000
/// corresponds to [`ipv4::IPv4`]).
///
/// In this function we just call the `register_defaults` functions for each of the currently
/// supported layers.
///
/// When a new layer is defined outside the crate, that particular layer may use a `register_*`
/// function in it's upper layer to request it's dissection. This glues all the dissectors for the
/// layers together.
"#;

    output_str += "pub fn register_defaults() -> Result<(), crate::errors::Error> {\n\t";

    output_str += "let mut result: Result<(), crate::errors::Error> = Ok(());";

    output_str += "fn inner() -> Result<(), crate::errors::Error> {";
    // We need to make sure `packet::register_defaults` is initialized first.
    output_str += "\n\tcrate::packet::register_defaults()?;\n\t";
    output_str += &reg_defaults.join("\n\t");
    output_str += "Ok(())";
    output_str += "}";
    output_str += "INIT.call_once(|| { ";
    output_str += "result = inner();";

    output_str += "});";
    output_str += "\n\n\tresult\n";
    output_str += "}";

    let output_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let outfile_path = output_path.join("register_defaults.rs");
    {
        let mut outfile = File::create(&outfile_path).unwrap();
        let _ = outfile.write(output_str.as_bytes());
        let _ = outfile.flush();
    }

    let _ = std::process::Command::new("rustfmt")
        .arg(&outfile_path)
        .output()
        .expect("Failed to rustfmt");

    Ok(())
}
