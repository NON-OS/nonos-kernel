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


use alloc::vec::Vec;
use super::types::{MicroParsed, PortRange};
use super::encoding::b64_32;
use crate::crypto::hash;

const MAX_MICRODESC_BYTES: usize = 64 * 1024;

pub(super) fn parse_microdesc(text: &Vec<u8>) -> Option<MicroParsed> {
    let s = core::str::from_utf8(text).ok()?;
    let mut out = MicroParsed::default();
    let mut lines = s.lines();

    while let Some(l) = lines.next() {
        if l.starts_with("onion-key ntor") {
            if let Some(kline) = lines.next() {
                if let Some(k) = b64_32(kline.trim()) {
                    out.ntor_key = k;
                }
            }
        } else if l.starts_with("family ") {
            out.family = l[7..].trim().into();
        } else if l.starts_with("p ") || l.starts_with("p6 ") {
            parse_exit_policy_line(l, &mut out.exit_ports);
        }
    }

    Some(out)
}

fn parse_exit_policy_line(line: &str, ports: &mut Vec<PortRange>) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return;
    }

    if parts[1] != "accept" {
        return;
    }

    for spec in parts[2].split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }

        if let Some(dash_pos) = spec.find('-') {
            let (min_str, max_str) = spec.split_at(dash_pos);
            let max_str = &max_str[1..];
            if let (Ok(min), Ok(max)) = (min_str.parse::<u16>(), max_str.parse::<u16>()) {
                ports.push(PortRange::new(min, max));
            }
        } else {
            if let Ok(port) = spec.parse::<u16>() {
                ports.push(PortRange::single(port));
            }
        }
    }
}

pub(super) fn split_microdesc_blobs(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let s = core::str::from_utf8(body).unwrap_or("");
    let mut cur = Vec::new();

    for line in s.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(cur.clone());
                cur.clear();
            }
        } else {
            cur.extend_from_slice(line.as_bytes());
            cur.extend_from_slice(b"\n");
            if cur.len() > MAX_MICRODESC_BYTES {
                cur.clear();
            }
        }
    }

    if !cur.is_empty() {
        out.push(cur);
    }

    out
}

pub(super) fn sha256_of_text(t: &Vec<u8>) -> Option<[u8; 32]> {
    let h = hash::sha256(t);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    Some(out)
}

pub(super) fn max_microdesc_size() -> usize {
    MAX_MICRODESC_BYTES
}
