// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

pub struct CapsuleConfig {
    pub id: String,
    pub name: String,
    pub version: String,
    pub dev_name: String,
    pub dev_addr: [u8; 20],
    pub caps: Vec<String>,
    pub mem_min: u64,
    pub mem_max: u64,
    pub cpu_shares: u32,
    pub price: u64,
}

impl Default for CapsuleConfig {
    fn default() -> Self {
        Self {
            id: String::new(), name: String::new(), version: String::from("1.0.0"),
            dev_name: String::new(), dev_addr: [0; 20], caps: Vec::new(),
            mem_min: 16 * 1024 * 1024, mem_max: 128 * 1024 * 1024, cpu_shares: 100, price: 0,
        }
    }
}

pub fn build_manifest(cfg: &CapsuleConfig, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut m = String::from("{\n");
    m.push_str(&alloc::format!("  \"id\": \"{}\",\n", cfg.id));
    m.push_str(&alloc::format!("  \"name\": \"{}\",\n", cfg.name));
    m.push_str(&alloc::format!("  \"version\": \"{}\",\n", cfg.version));
    m.push_str("  \"developer\": {\n");
    m.push_str(&alloc::format!("    \"name\": \"{}\",\n", cfg.dev_name));
    m.push_str(&alloc::format!("    \"address\": \"0x{}\",\n", hex_encode(&cfg.dev_addr)));
    m.push_str(&alloc::format!("    \"pubkey\": \"ed25519:{}\"\n", base64_encode(pubkey)));
    m.push_str("  },\n");
    m.push_str("  \"capabilities\": [");
    for (i, c) in cfg.caps.iter().enumerate() {
        if i > 0 { m.push_str(", "); }
        m.push_str(&alloc::format!("\"{}\"", c));
    }
    m.push_str("],\n");
    m.push_str("  \"resources\": {\n");
    m.push_str(&alloc::format!("    \"memory_min\": \"{}MB\",\n", cfg.mem_min / (1024 * 1024)));
    m.push_str(&alloc::format!("    \"memory_max\": \"{}MB\",\n", cfg.mem_max / (1024 * 1024)));
    m.push_str(&alloc::format!("    \"cpu_shares\": {}\n", cfg.cpu_shares));
    m.push_str("  },\n");
    m.push_str("  \"pricing\": {\n");
    m.push_str("    \"model\": \"per_session\",\n");
    m.push_str(&alloc::format!("    \"amount\": {},\n", cfg.price));
    m.push_str("    \"token\": \"NOX\"\n");
    m.push_str("  }\n}\n");
    m.into_bytes()
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data { s.push_str(&alloc::format!("{:02x}", b)); }
    s
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        s.push(ALPHA[(b0 >> 2) & 0x3F] as char);
        s.push(ALPHA[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);
        s.push(if chunk.len() > 1 { ALPHA[((b1 << 2) | (b2 >> 6)) & 0x3F] as char } else { '=' });
        s.push(if chunk.len() > 2 { ALPHA[b2 & 0x3F] as char } else { '=' });
    }
    s
}
