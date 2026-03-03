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


use alloc::{string::String, vec::Vec};

pub(super) fn b64_20(s: &str) -> Option<[u8; 20]> {
    let v = b64_any(s)?;
    if v.len() != 20 { return None; }
    let mut a = [0u8; 20];
    a.copy_from_slice(&v);
    Some(a)
}

pub(super) fn b64_32(s: &str) -> Option<[u8; 32]> {
    let v = b64_any(s)?;
    if v.len() != 32 { return None; }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

pub(super) fn b64_any(s: &str) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity((s.len() * 3) / 4 + 3);
    let mut quart = [0u8; 4];
    let mut qn = 0usize;

    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => None,
            _ => None,
        }
    }

    for &b in s.as_bytes() {
        if b == b'=' {
            quart[qn] = 0;
            qn += 1;
            if qn == 4 {
                decode_quart(&quart, &mut buf);
                qn = 0;
            }
            continue;
        }
        if let Some(v) = val(b) {
            quart[qn] = v;
            qn += 1;
            if qn == 4 {
                decode_quart(&quart, &mut buf);
                qn = 0;
            }
        }
    }

    if qn > 0 {
        for i in qn..4 {
            quart[i] = 0;
        }
        decode_quart(&quart, &mut buf);
        let rem = qn.saturating_sub(1);
        if rem == 2 {
            buf.truncate(buf.len().saturating_sub(1));
        }
        if rem == 1 {
            buf.truncate(buf.len().saturating_sub(2));
        }
    }

    Some(buf)
}

fn decode_quart(q: &[u8; 4], out: &mut Vec<u8>) {
    let n = ((q[0] as u32) << 18) | ((q[1] as u32) << 12) | ((q[2] as u32) << 6) | (q[3] as u32);
    out.push(((n >> 16) & 0xFF) as u8);
    out.push(((n >> 8) & 0xFF) as u8);
    out.push((n & 0xFF) as u8);
}

pub(super) fn b64_url_nopad(bytes: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0usize;

    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPH[((n >> 18) & 63) as usize] as char);
        out.push(ALPH[((n >> 12) & 63) as usize] as char);
        out.push(ALPH[((n >> 6) & 63) as usize] as char);
        out.push(ALPH[(n & 63) as usize] as char);
        i += 3;
    }

    if i < bytes.len() {
        let rem = bytes.len() - i;
        let b0 = bytes[i] as u32;
        let b1 = if rem > 1 { bytes[i + 1] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8);
        out.push(ALPH[((n >> 18) & 63) as usize] as char);
        out.push(ALPH[((n >> 12) & 63) as usize] as char);
        if rem == 2 {
            out.push(ALPH[((n >> 6) & 63) as usize] as char);
        }
    }

    out
}

pub(super) fn hex20(s: &str) -> Option<[u8; 20]> {
    let v = hex_to_vec(s).ok()?;
    if v.len() != 20 { return None; }
    let mut a = [0u8; 20];
    a.copy_from_slice(&v);
    Some(a)
}

pub(super) fn hex_to_vec(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;

    while i + 1 < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or("Invalid hex character")?;
        let lo = hex_val(bytes[i + 1]).ok_or("Invalid hex character")?;
        out.push((hi << 4) | lo);
        i += 2;
    }

    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
