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
        0x02 => handle_mount(data, &mut response),
        0x03 => handle_unmount(data, &mut response),
        0x04 => handle_get(data, &mut response),
        0x05 => handle_count(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_register(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 18 {
        resp[0] = 0xFE;
        return;
    }
    let name_len = data[1] as usize;
    if data.len() < 2 + name_len + 12 {
        resp[0] = 0xFE;
        return;
    }
    let off = 2 + name_len;
    let sector_size = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let sector_count = u64::from_le_bytes([
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
        data[off + 8],
        data[off + 9],
        data[off + 10],
        data[off + 11],
    ]);
    if let Some(id) = manager::register_device(&data[2..2 + name_len], sector_size, sector_count) {
        resp[0] = 0x01;
        resp[1] = id;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_mount(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 2 {
        resp[0] = 0xFE;
        return;
    }
    if manager::mount_device(data[1]) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_unmount(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 2 {
        resp[0] = 0xFE;
        return;
    }
    if manager::unmount_device(data[1]) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_get(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 2 {
        resp[0] = 0xFE;
        return;
    }
    if let Some(dev) = manager::get_device(data[1]) {
        resp[0] = 0x01;
        resp[1] = dev.id;
        resp[2..18].copy_from_slice(&dev.name);
        resp[18..22].copy_from_slice(&dev.sector_size.to_le_bytes());
        resp[22..30].copy_from_slice(&dev.sector_count.to_le_bytes());
        resp[30] = if dev.mounted { 1 } else { 0 };
    } else {
        resp[0] = 0x02;
    }
}

fn handle_count(resp: &mut [u8; 128]) {
    resp[0] = 0x01;
    resp[1] = manager::device_count();
}
