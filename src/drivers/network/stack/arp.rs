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

use alloc::collections::BTreeMap;
use spin::Mutex;

use super::filter::run_send;
use super::headers::{be16, to_be16, ETH_HDR, ET_ARP, ET_IPV4};
use super::interface::{get_default_interface, get_ipv4};

static ARP_CACHE: Mutex<BTreeMap<[u8; 4], [u8; 6]>> = Mutex::new(BTreeMap::new());

pub fn arp_lookup(ip: [u8; 4]) -> Option<[u8; 6]> {
    ARP_CACHE.lock().get(&ip).cloned()
}

pub fn arp_insert(ip: [u8; 4], mac: [u8; 6]) {
    ARP_CACHE.lock().insert(ip, mac);
}

pub(super) fn send_arp_request(target_ip: [u8; 4]) -> Result<(), &'static str> {
    let iface = get_default_interface().ok_or("no default iface")?;
    let src_mac = iface.get_mac_address();
    let src_ip = get_ipv4();
    let mut frame = [0u8; ETH_HDR + 28];
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&to_be16(ET_ARP));
    let p = &mut frame[ETH_HDR..];
    p[0..2].copy_from_slice(&to_be16(1));
    p[2..4].copy_from_slice(&to_be16(ET_IPV4));
    p[4] = 6;
    p[5] = 4;
    p[6..8].copy_from_slice(&to_be16(1));
    p[8..14].copy_from_slice(&src_mac);
    p[14..18].copy_from_slice(&src_ip);
    p[18..24].copy_from_slice(&[0u8; 6]);
    p[24..28].copy_from_slice(&target_ip);
    if !run_send(&frame) {
        return Err("send filtered");
    }
    iface.send_packet(&frame)
}

pub(super) fn handle_arp(payload: &[u8]) {
    if payload.len() < 28 {
        crate::log_warn!("network: ARP packet too short ({} < 28)", payload.len());
        return;
    }
    let oper = be16([payload[6], payload[7]]);
    let sha = <[u8; 6]>::try_from(&payload[8..14]).unwrap_or([0; 6]);
    let spa = <[u8; 4]>::try_from(&payload[14..18]).unwrap_or([0; 4]);
    let tha = <[u8; 6]>::try_from(&payload[18..24]).unwrap_or([0; 6]);
    let tpa = <[u8; 4]>::try_from(&payload[24..28]).unwrap_or([0; 4]);
    arp_insert(spa, sha);
    if oper == 1 && tpa == get_ipv4() {
        if let Some(iface) = get_default_interface() {
            let src_mac = iface.get_mac_address();
            let src_ip = get_ipv4();
            let mut frame = [0u8; ETH_HDR + 28];
            frame[0..6].copy_from_slice(&sha);
            frame[6..12].copy_from_slice(&src_mac);
            frame[12..14].copy_from_slice(&to_be16(ET_ARP));
            let p = &mut frame[ETH_HDR..];
            p[0..2].copy_from_slice(&to_be16(1));
            p[2..4].copy_from_slice(&to_be16(ET_IPV4));
            p[4] = 6;
            p[5] = 4;
            p[6..8].copy_from_slice(&to_be16(2));
            p[8..14].copy_from_slice(&src_mac);
            p[14..18].copy_from_slice(&src_ip);
            p[18..24].copy_from_slice(&tha);
            p[24..28].copy_from_slice(&spa);
            if let Err(e) = iface.send_packet(&frame) {
                crate::log_warn!("network: ARP reply send failed: {}", e);
            }
        }
    }
}
