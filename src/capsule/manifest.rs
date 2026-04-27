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
use super::caps::cap_from_str;
use alloc::string::String;

#[derive(Debug, Clone)]
pub struct Manifest {
    pub id: [u8; 32],
    pub name: String,
    pub version: u32,
    pub dev_addr: [u8; 20],
    pub dev_pubkey: [u8; 32],
    pub caps: u64,
    pub mem_min: u64,
    pub mem_max: u64,
    pub cpu_shares: u32,
    pub price: u64,
}

#[derive(Debug)]
pub enum ManifestError {
    InvalidJson,
    MissingField,
    InvalidHex,
}

impl Manifest {
    pub fn parse(data: &[u8]) -> Result<Self, ManifestError> {
        let s = core::str::from_utf8(data).map_err(|_| ManifestError::InvalidJson)?;
        let id = Self::extract_hash(s, "id")?;
        let name = Self::extract_str(s, "name").unwrap_or_default();
        let version = Self::extract_num(s, "version").unwrap_or(1) as u32;
        let dev_addr = Self::extract_addr(s, "address").unwrap_or([0; 20]);
        let dev_pubkey = Self::extract_key(s, "pubkey").unwrap_or([0; 32]);
        let caps = Self::extract_caps(s);
        let mem_min = Self::parse_size(Self::extract_str(s, "memory_min").as_deref());
        let mem_max = Self::parse_size(Self::extract_str(s, "memory_max").as_deref());
        let cpu_shares = Self::extract_num(s, "cpu_shares").unwrap_or(100) as u32;
        let price = Self::extract_num(s, "amount").unwrap_or(0);
        Ok(Self {
            id,
            name,
            version,
            dev_addr,
            dev_pubkey,
            caps,
            mem_min,
            mem_max,
            cpu_shares,
            price,
        })
    }

    fn extract_str(j: &str, k: &str) -> Option<String> {
        let p = alloc::format!("\"{}\"", k);
        let i = j.find(&p)?;
        let r = &j[i + p.len()..];
        let c = r.find(':')?;
        let a = r[c + 1..].trim_start();
        if !a.starts_with('"') {
            return None;
        }
        let e = a[1..].find('"')?;
        Some(a[1..1 + e].into())
    }

    fn extract_num(j: &str, k: &str) -> Option<u64> {
        let p = alloc::format!("\"{}\"", k);
        let i = j.find(&p)?;
        let r = &j[i + p.len()..];
        let c = r.find(':')?;
        let a = r[c + 1..].trim_start();
        let e = a.find(|c: char| !c.is_ascii_digit()).unwrap_or(a.len());
        a[..e].parse().ok()
    }

    fn extract_hash(j: &str, k: &str) -> Result<[u8; 32], ManifestError> {
        let s = Self::extract_str(j, k).ok_or(ManifestError::MissingField)?;
        let mut h = [0u8; 32];
        let b = crate::crypto::keccak::keccak256(s.as_bytes());
        h.copy_from_slice(&b);
        Ok(h)
    }

    fn extract_addr(j: &str, k: &str) -> Option<[u8; 20]> {
        let s = Self::extract_str(j, k)?;
        if s.len() < 42 || !s.starts_with("0x") {
            return None;
        }
        let mut a = [0u8; 20];
        for (i, chunk) in s[2..42].as_bytes().chunks(2).enumerate() {
            a[i] = u8::from_str_radix(core::str::from_utf8(chunk).ok()?, 16).ok()?;
        }
        Some(a)
    }

    fn extract_key(j: &str, k: &str) -> Option<[u8; 32]> {
        let s = Self::extract_str(j, k)?;
        let d = s.strip_prefix("ed25519:")?;
        let b = crate::crypto::base64::decode(d).ok()?;
        if b.len() < 32 {
            return None;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&b[..32]);
        Some(k)
    }

    fn extract_caps(j: &str) -> u64 {
        let mut caps = 0u64;
        if let Some(i) = j.find("\"capabilities\"") {
            if let Some(s) = j[i..].find('[') {
                if let Some(e) = j[i + s..].find(']') {
                    let arr = &j[i + s + 1..i + s + e];
                    for cap in arr.split('"').filter(|s| s.len() > 2) {
                        caps |= cap_from_str(cap.trim());
                    }
                }
            }
        }
        caps
    }

    fn parse_size(s: Option<&str>) -> u64 {
        let s = s.unwrap_or("64MB").trim();
        let (n, m) = if s.ends_with("GB") {
            (&s[..s.len() - 2], 1024 * 1024 * 1024)
        } else if s.ends_with("MB") {
            (&s[..s.len() - 2], 1024 * 1024)
        } else if s.ends_with("KB") {
            (&s[..s.len() - 2], 1024)
        } else {
            (s, 1)
        };
        n.trim().parse::<u64>().unwrap_or(64) * m
    }
}
