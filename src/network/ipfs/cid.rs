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

pub fn validate(cid: &str) -> bool {
    if cid.len() < 46 { return false; }
    if cid.starts_with("Qm") && cid.len() == 46 { return cid.chars().all(|c| c.is_alphanumeric()); }
    if cid.starts_with("bafy") { return cid.chars().all(|c| c.is_alphanumeric()); }
    false
}

pub fn from_sha256(hash: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(34);
    buf.push(0x12);
    buf.push(0x20);
    buf.extend_from_slice(hash);
    base58_encode(&buf)
}

pub fn verify_content(data: &[u8], cid: &str) -> bool {
    let hash = crate::crypto::sha256::hash(data);
    from_sha256(&hash) == cid
}

fn base58_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = Vec::new();
    let mut num = data.to_vec();
    while !num.is_empty() && !num.iter().all(|&b| b == 0) {
        let mut rem = 0u32;
        let mut new_num = Vec::new();
        for &b in &num {
            let acc = (rem << 8) | b as u32;
            let q = acc / 58;
            rem = acc % 58;
            if !new_num.is_empty() || q > 0 { new_num.push(q as u8); }
        }
        result.push(ALPHA[rem as usize]);
        num = new_num;
    }
    for &b in data { if b == 0 { result.push(b'1'); } else { break; } }
    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}
