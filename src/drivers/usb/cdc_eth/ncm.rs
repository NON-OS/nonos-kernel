// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

extern crate alloc;

use alloc::vec::Vec;

pub fn wrap_ntb(frame: &[u8]) -> Vec<u8> {
    let nth_len = 12;
    let ndp_len = 16;
    let total_len = nth_len + ndp_len + frame.len();

    let mut ntb = Vec::with_capacity(total_len);

    ntb.extend_from_slice(b"NCMH");
    ntb.extend_from_slice(&12u16.to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());
    ntb.extend_from_slice(&(total_len as u16).to_le_bytes());
    ntb.extend_from_slice(&12u16.to_le_bytes());

    ntb.extend_from_slice(b"NCM0");
    ntb.extend_from_slice(&16u16.to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());
    ntb.extend_from_slice(&((nth_len + ndp_len) as u16).to_le_bytes());
    ntb.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());

    ntb.extend_from_slice(frame);

    ntb
}

pub fn unwrap_ntb(data: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();

    if data.len() < 12 {
        return packets;
    }

    if &data[0..4] != b"NCMH" {
        return packets;
    }

    let block_len = u16::from_le_bytes([data[8], data[9]]) as usize;
    let ndp_index = u16::from_le_bytes([data[10], data[11]]) as usize;

    if block_len > data.len() || ndp_index >= data.len() {
        return packets;
    }

    if ndp_index + 8 > data.len() {
        return packets;
    }

    if &data[ndp_index..ndp_index + 4] != b"NCM0" && &data[ndp_index..ndp_index + 4] != b"NCM1" {
        return packets;
    }

    let ndp_len = u16::from_le_bytes([data[ndp_index + 4], data[ndp_index + 5]]) as usize;

    let mut offset = ndp_index + 8;
    while offset + 4 <= ndp_index + ndp_len && offset + 4 <= data.len() {
        let dg_index = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let dg_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if dg_index == 0 && dg_len == 0 {
            break;
        }

        if dg_index + dg_len <= data.len() && dg_len >= 14 {
            packets.push(data[dg_index..dg_index + dg_len].to_vec());
        }

        offset += 4;
    }

    packets
}
