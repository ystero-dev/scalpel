use clap::Parser;

#[derive(Parser, Debug)]
struct Opts {
    /// Device to open (defaults to `any`)
    #[arg(short, long, default_value = "any")]
    device: String,

    /// Number of packets to capture
    #[arg(short)]
    num_packets: Option<u32>,
}

#[cfg(not(feature = "wasm"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use pcap::{Capture, Device, Linktype};

    // Command Line Handling
    let opts = Opts::parse();

    let device: Device = (&*opts.device).into();

    eprintln!("Using device: {}", device.name);

    let mut cap = Capture::from_device(device)?.immediate_mode(true).open()?;

    eprintln!("DataLink: {:#?}", cap.get_datalink());
    // `register_defaults` need to be called to setup decoders.
    let _ = scalpel::register_defaults();
    let encap_type = match cap.get_datalink() {
        Linktype::LINUX_SLL => scalpel::ENCAP_TYPE_LINUX_SLL,
        Linktype::LINUX_SLL2 => scalpel::ENCAP_TYPE_LINUX_SLL2,
        Linktype::ETHERNET => scalpel::ENCAP_TYPE_ETH,
        _ => todo!(),
    };

    let mut counter = 0;
    while let Ok(packet) = cap.next_packet() {
        if let Some(num_packets) = opts.num_packets {
            if counter >= num_packets {
                break;
            }
        }
        counter += 1;

        eprintln!("packet.data: {}", hex::encode(packet.data));
        let p = scalpel::Packet::from_bytes(&packet.data, encap_type);
        match p {
            Ok(p) => println!("{}", serde_json::to_string_pretty(&p).unwrap()),
            Err(e) => {
                eprintln!("Err: {:?}, data: {:?}", e, hex::encode(packet.data));
            }
        }
        // print the json of the packet.
    }

    Ok(())
}

#[cfg(feature = "wasm")]
fn main() {}
