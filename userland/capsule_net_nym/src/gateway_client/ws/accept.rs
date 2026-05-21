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

use super::{base64, sha1};

const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn verify(resp: &[u8], key: &[u8]) -> bool {
    if !resp.starts_with(b"HTTP/1.1 101") && !resp.starts_with(b"HTTP/1.0 101") {
        return false;
    }
    let mut data = [0u8; 64];
    data[..key.len()].copy_from_slice(key);
    data[key.len()..key.len() + GUID.len()].copy_from_slice(GUID);
    let digest = sha1::digest(&data[..key.len() + GUID.len()]);
    let mut expect = [0u8; 32];
    let Some(n) = base64::encode(&digest, &mut expect) else { return false };
    find_accept(resp, &expect[..n])
}

fn find_accept(resp: &[u8], expect: &[u8]) -> bool {
    for line in resp.split(|b| *b == b'\n') {
        let line = trim_cr(line);
        if line.len() < 21 || !prefix(line, b"sec-websocket-accept:") {
            continue;
        }
        if trim_space(&line[21..]) == expect {
            return true;
        }
    }
    false
}

fn prefix(line: &[u8], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(v) => v,
        None => line,
    }
}

fn trim_space(mut v: &[u8]) -> &[u8] {
    while v.first() == Some(&b' ') {
        v = &v[1..];
    }
    v
}
