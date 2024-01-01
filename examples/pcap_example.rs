use clap::Parser;
use pcap::{Capture, Device};

#[derive(Parser, Debug)]
struct Opts {
    /// Device to open (defaults to `any`)
    #[arg(short, long, default_value = "any")]
    device: String,

    /// Number of packets to capture
    #[arg(short)]
    num_packets: Option<u32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Command Line Handling
    let opts = Opts::parse();

    let device: Device = (&*opts.device).into();

    eprintln!("Using device: {}", device.name);

    let mut cap = Capture::from_device(device)?.immediate_mode(true).open()?;

    // `register_defaults` need to be called to setup decoders.
    let _ = scalpel::register_defaults();

    while let Ok(packet) = cap.next_packet() {
        let p = scalpel::Packet::from_bytes(&packet.data, scalpel::ENCAP_TYPE_ETH);
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
