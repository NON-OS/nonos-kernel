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

use super::manager;

pub(super) fn process_request(data: &[u8]) -> [u8; 128] {
    let mut response = [0u8; 128];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_register(data, &mut response),
        0x02 => handle_set_ip(data, &mut response),
        0x03 => handle_set_up(data, &mut response),
        0x04 => handle_get_interface(data, &mut response),
        0x05 => handle_count(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_register(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 23 {
        resp[0] = 0xFE;
        return;
    }
    let name_len = data[1] as usize;
    if data.len() < 2 + name_len + 6 {
        resp[0] = 0xFE;
        return;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&data[2 + name_len..2 + name_len + 6]);
    if let Some(idx) = manager::register_interface(&data[2..2 + name_len], &mac) {
        resp[0] = 0x01;
        resp[1] = idx;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_set_ip(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 14 {
        resp[0] = 0xFE;
        return;
    }
    let idx = data[1];
    let ipv4 = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let netmask = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
    let gateway = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
    if manager::set_ipv4(idx, ipv4, netmask, gateway) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_set_up(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 3 {
        resp[0] = 0xFE;
        return;
    }
    if manager::set_up(data[1], data[2] != 0) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_get_interface(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 2 {
        resp[0] = 0xFE;
        return;
    }
    if let Some(iface) = manager::get_interface(data[1]) {
        resp[0] = 0x01;
        resp[1..17].copy_from_slice(&iface.name);
        resp[17..23].copy_from_slice(&iface.mac);
        resp[23..27].copy_from_slice(&iface.ipv4.to_le_bytes());
        resp[27..31].copy_from_slice(&iface.netmask.to_le_bytes());
        resp[31..35].copy_from_slice(&iface.gateway.to_le_bytes());
        resp[35] = if iface.up { 1 } else { 0 };
        resp[36] = if iface.dhcp { 1 } else { 0 };
    } else {
        resp[0] = 0x02;
    }
}

fn handle_count(resp: &mut [u8; 128]) {
    resp[0] = 0x01;
    resp[1] = manager::interface_count();
}
