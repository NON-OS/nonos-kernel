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

pub(super) fn starts_no_case(s: &[u8], pref: &[u8]) -> bool {
    if s.len() < pref.len() { return false; }
    s[..pref.len()].eq_ignore_ascii_case(pref)
}

pub(super) fn parse_usize_ascii(s: &[u8]) -> Result<usize, ()> {
    let mut n: usize = 0;
    for &b in s {
        if b == b' ' || b == b'\r' { break; }
        if !(b'0'..=b'9').contains(&b) { return Err(()); }
        n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
    }
    Ok(n)
}

pub(super) fn find_subsequence(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() { return Some(0); }
    h.windows(n.len()).position(|w| w == n)
}

pub(super) fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() { sum += (data[i] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

pub(super) fn build_ipv4_packet(src: &[u8; 4], dst: &[u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0x4E4Fu16.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(protocol);
    pkt.push(0);
    pkt.push(0);
    pkt.extend_from_slice(src);
    pkt.extend_from_slice(dst);
    let cksum = ip_checksum(&pkt[..20]);
    pkt[10] = (cksum >> 8) as u8;
    pkt[11] = (cksum & 0xFF) as u8;
    pkt.extend_from_slice(payload);
    pkt
}

pub(super) fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        if i == 10 { i += 2; continue; }
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

pub(super) fn build_ethernet_frame(src_mac: &[u8; 6], dst_mac: &[u8], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
