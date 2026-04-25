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

use super::engine;

pub(super) fn process_request(data: &[u8]) -> [u8; 256] {
    let mut response = [0u8; 256];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_sha3_256(data, &mut response),
        0x03 => handle_sha3_512(data, &mut response),
        0x04 => handle_keccak_256(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_sha3_256(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 3 {
        resp[0] = 0xFE;
        return;
    }
    let len = u16::from_le_bytes([data[1], data[2]]) as usize;
    if len > 200 || data.len() < 3 + len {
        resp[0] = 0xFE;
        return;
    }
    let mut output = [0u8; 32];
    engine::sha3_256(&data[3..3 + len], &mut output);
    resp[0] = 0x01;
    resp[1] = 32;
    resp[2..34].copy_from_slice(&output);
}

fn handle_sha3_512(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 3 {
        resp[0] = 0xFE;
        return;
    }
    let len = u16::from_le_bytes([data[1], data[2]]) as usize;
    if len > 200 || data.len() < 3 + len {
        resp[0] = 0xFE;
        return;
    }
    let mut output = [0u8; 64];
    engine::sha3_512(&data[3..3 + len], &mut output);
    resp[0] = 0x01;
    resp[1] = 64;
    resp[2..66].copy_from_slice(&output);
}

fn handle_keccak_256(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 3 {
        resp[0] = 0xFE;
        return;
    }
    let len = u16::from_le_bytes([data[1], data[2]]) as usize;
    if len > 200 || data.len() < 3 + len {
        resp[0] = 0xFE;
        return;
    }
    let mut output = [0u8; 32];
    engine::keccak_256(&data[3..3 + len], &mut output);
    resp[0] = 0x01;
    resp[1] = 32;
    resp[2..34].copy_from_slice(&output);
}

fn handle_get_stats(resp: &mut [u8; 256]) {
    let (hashes, bytes) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&hashes.to_le_bytes());
    resp[9..17].copy_from_slice(&bytes.to_le_bytes());
}
