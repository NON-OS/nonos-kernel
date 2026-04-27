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

use super::devices;

pub(super) fn process_request(data: &[u8]) -> [u8; 128] {
    let mut response = [0u8; 128];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_register(data, &mut response),
        0x02 => handle_unregister(data, &mut response),
        0x03 => handle_get(data, &mut response),
        0x04 => handle_count(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_register(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 40 {
        resp[0] = 0xFE;
        return;
    }
    let name_len = data[1] as usize;
    if data.len() < 2 + name_len + 6 {
        resp[0] = 0xFE;
        return;
    }
    let off = 2 + name_len;
    let class = data[off];
    let subclass = data[off + 1];
    let vid = u16::from_le_bytes([data[off + 2], data[off + 3]]);
    let pid = u16::from_le_bytes([data[off + 4], data[off + 5]]);
    let id = devices::register_device(&data[2..2 + name_len], class, subclass, vid, pid);
    if id > 0 {
        resp[0] = 0x01;
        resp[1..5].copy_from_slice(&id.to_le_bytes());
    } else {
        resp[0] = 0x02;
    }
}

fn handle_unregister(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 5 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if devices::unregister_device(id) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_get(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 5 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if let Some(dev) = devices::get_device(id) {
        resp[0] = 0x01;
        resp[1..5].copy_from_slice(&dev.id.to_le_bytes());
        resp[5..37].copy_from_slice(&dev.name);
        resp[37] = dev.class;
        resp[38] = dev.subclass;
        resp[39..41].copy_from_slice(&dev.vendor_id.to_le_bytes());
        resp[41..43].copy_from_slice(&dev.product_id.to_le_bytes());
    } else {
        resp[0] = 0x02;
    }
}

fn handle_count(resp: &mut [u8; 128]) {
    resp[0] = 0x01;
    resp[1..5].copy_from_slice(&devices::device_count().to_le_bytes());
}
