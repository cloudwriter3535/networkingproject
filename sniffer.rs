extern crate pcap;

use pcap::Device;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Config {
    interface: String,
}

#[derive(Serialize)]
struct PacketLog {
    timestamp: u128,
    length: u32,
    data: Vec<u8>,
}

pub struct Sniffer {
    config: Config,
}

impl Sniffer {
    pub fn new() -> Self {
        Sniffer {
            config: Config {
                interface: String::new(),
            },
        }
    }

    pub fn load_config(&mut self, file_path: &str) {
        let config_data = std::fs::read_to_string(file_path).expect("Unable to read config file");
        self.config = toml::from_str(&config_data).expect("Unable to parse config file");
    }

    pub fn start(&mut self) {
        let device = Device::list()
            .expect("Failed to list devices")
            .into_iter()
            .find(|d| d.name == self.config.interface)
            .expect("Failed to find specified device");

        println!("Using device: {}", device.name);

        let mut cap = device.open().expect("Failed to open device");

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("logs/packets.log")
            .expect("Failed to open log file");

        while let Ok(packet) = cap.next() {
            let packet_log = PacketLog {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis(),
                length: packet.header.len,
                data: packet.data.to_vec(),
            };

            let json = serde_json::to_string(&packet_log).expect("Failed to serialize packet");

            writeln!(file, "{}", json).expect("Failed to write to log file");

            println!("Captured packet with length: {}", packet.header.len);
        }
    }
}

