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
        0x01 => handle_hash(data, &mut response),
        0x02 => handle_keyed_hash(data, &mut response),
        0x03 => handle_derive_key(data, &mut response),
        0x04 => handle_hash_xof(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_hash(data: &[u8], resp: &mut [u8; 256]) {
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
    engine::hash(&data[3..3 + len], &mut output);
    resp[0] = 0x01;
    resp[1] = 32;
    resp[2..34].copy_from_slice(&output);
}

fn handle_keyed_hash(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 35 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[1..33]);
    let len = u16::from_le_bytes([data[33], data[34]]) as usize;
    if len > 200 || data.len() < 35 + len {
        resp[0] = 0xFE;
        return;
    }
    let mut output = [0u8; 32];
    engine::keyed_hash(&key, &data[35..35 + len], &mut output);
    resp[0] = 0x01;
    resp[1] = 32;
    resp[2..34].copy_from_slice(&output);
}

fn handle_derive_key(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 5 {
        resp[0] = 0xFE;
        return;
    }
    let ctx_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    let inp_len = u16::from_le_bytes([data[3], data[4]]) as usize;
    if ctx_len > 100 || inp_len > 100 || data.len() < 5 + ctx_len + inp_len {
        resp[0] = 0xFE;
        return;
    }
    let mut output = [0u8; 32];
    let context = &data[5..5 + ctx_len];
    let input = &data[5 + ctx_len..5 + ctx_len + inp_len];
    engine::derive_key(context, input, &mut output);
    resp[0] = 0x01;
    resp[1] = 32;
    resp[2..34].copy_from_slice(&output);
}

fn handle_hash_xof(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 4 {
        resp[0] = 0xFE;
        return;
    }
    let input_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    let out_len = data[3] as usize;
    if input_len > 180 || out_len > 64 || data.len() < 4 + input_len {
        resp[0] = 0xFE;
        return;
    }
    engine::hash_xof(&data[4..4 + input_len], &mut resp[2..2 + out_len], out_len);
    resp[0] = 0x01;
    resp[1] = out_len as u8;
}

fn handle_get_stats(resp: &mut [u8; 256]) {
    let (hashes, bytes) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&hashes.to_le_bytes());
    resp[9..17].copy_from_slice(&bytes.to_le_bytes());
}
