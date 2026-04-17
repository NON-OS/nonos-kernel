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
use alloc::vec::Vec;
use spin::Mutex;
use super::address::{Ipv6Address, Ipv6Cidr};
use super::routing::add_route;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaacState { Idle, Tentative, Preferred, Deprecated }

#[derive(Debug, Clone)]
pub struct SlaacConfig {
    pub address: Ipv6Address,
    pub prefix_len: u8,
    pub state: SlaacState,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub created: u64,
}

static SLAAC_STATE: Mutex<Vec<SlaacConfig>> = Mutex::new(Vec::new());

pub fn generate_interface_id(mac: &[u8; 6]) -> [u8; 8] {
    let mut iid = [0u8; 8];
    iid[0] = mac[0] ^ 0x02;
    iid[1] = mac[1];
    iid[2] = mac[2];
    iid[3] = 0xff;
    iid[4] = 0xfe;
    iid[5] = mac[3];
    iid[6] = mac[4];
    iid[7] = mac[5];
    iid
}

pub fn generate_link_local(mac: &[u8; 6]) -> Ipv6Address {
    let iid = generate_interface_id(mac);
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[8..16].copy_from_slice(&iid);
    Ipv6Address(addr)
}

pub fn generate_global_address(prefix: &[u8], prefix_len: u8, mac: &[u8; 6]) -> Ipv6Address {
    let iid = generate_interface_id(mac);
    let mut addr = [0u8; 16];
    let prefix_bytes = (prefix_len / 8) as usize;
    addr[..prefix_bytes.min(prefix.len())].copy_from_slice(&prefix[..prefix_bytes.min(prefix.len())]);
    addr[8..16].copy_from_slice(&iid);
    Ipv6Address(addr)
}

pub fn perform_slaac(mac: &[u8; 6]) -> Ipv6Address {
    let link_local = generate_link_local(mac);
    let now = crate::sys::clock::uptime_ms();
    let cfg = SlaacConfig { address: link_local, prefix_len: 64, state: SlaacState::Tentative,
        valid_lifetime: u32::MAX, preferred_lifetime: u32::MAX, created: now };
    SLAAC_STATE.lock().push(cfg);
    link_local
}

pub fn process_ra(src: &Ipv6Address, data: &[u8]) {
    if data.len() < 12 { return; }
    let router_lifetime = u16::from_be_bytes([data[2], data[3]]);
    if router_lifetime > 0 {
        super::routing::add_default_route(*src, 0);
    }
    let mut offset = 12;
    while offset + 2 <= data.len() {
        let opt_type = data[offset];
        let opt_len = match (data[offset + 1] as usize).checked_mul(8) {
            Some(len) if len > 0 => len,
            _ => break,
        };
        if offset.saturating_add(opt_len) > data.len() { break; }
        if opt_type == 3 && opt_len >= 32 {
            let prefix_len = data[offset + 2];
            let valid = u32::from_be_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
            let pref = u32::from_be_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
            let mut prefix = [0u8; 16];
            prefix.copy_from_slice(&data[offset+16..offset+32]);
            if let Some(mac) = crate::network::get_mac_address() {
                let addr = generate_global_address(&prefix, prefix_len, &mac);
                let now = crate::sys::clock::uptime_ms();
                let cfg = SlaacConfig { address: addr, prefix_len, state: SlaacState::Tentative, valid_lifetime: valid, preferred_lifetime: pref, created: now };
                SLAAC_STATE.lock().push(cfg);
                add_route(Ipv6Cidr::new(Ipv6Address(prefix), prefix_len), None, 0, 256);
            }
        }
        offset += opt_len;
    }
}

pub fn get_slaac_addresses() -> Vec<SlaacConfig> { SLAAC_STATE.lock().clone() }

pub fn confirm_address(addr: &Ipv6Address) {
    for cfg in SLAAC_STATE.lock().iter_mut() {
        if &cfg.address == addr && cfg.state == SlaacState::Tentative { cfg.state = SlaacState::Preferred; }
    }
}
