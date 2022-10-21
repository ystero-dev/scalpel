use pcap::{Capture, Device};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `register_defaults` need to be called to setup decoders.
    let _ = scalpel::register_defaults();

    let device = Device::lookup()?.ok_or("no device available")?;

    eprintln!("Using device: {}", device.name);

    let mut cap = Capture::from_device(device)?.immediate_mode(true).open()?;

    while let Ok(packet) = cap.next_packet() {
        let p = scalpel::packet::Packet::from_bytes(&packet.data, scalpel::types::ENCAP_TYPE_ETH);
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
