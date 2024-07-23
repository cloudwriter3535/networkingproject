mod sniffer;

use sniffer::Sniffer;

fn main() {
    let mut sniffer = Sniffer::new();
    sniffer.load_config("config/config.toml");
    sniffer.start();
}

