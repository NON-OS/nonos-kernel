// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use super::{Request, HDR_LEN, MAGIC, VERSION};

pub fn parse(buf: &[u8]) -> Option<(Request, &[u8])> {
    if buf.len() < HDR_LEN || le32(&buf[0..4]) != MAGIC || le16(&buf[4..6]) != VERSION {
        return None;
    }
    let payload_len = le32(&buf[16..20]) as usize;
    if payload_len > buf.len().saturating_sub(HDR_LEN) {
        return None;
    }
    Some((
        Request { op: le16(&buf[6..8]), request_id: le32(&buf[12..16]) },
        &buf[HDR_LEN..HDR_LEN + payload_len],
    ))
}

fn le16(x: &[u8]) -> u16 {
    u16::from_le_bytes([x[0], x[1]])
}

fn le32(x: &[u8]) -> u32 {
    u32::from_le_bytes([x[0], x[1], x[2], x[3]])
}
