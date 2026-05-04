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

pub(super) fn process_request(data: &[u8]) -> [u8; 512] {
    let mut response = [0u8; 512];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_encrypt(data, &mut response),
        0x02 => handle_decrypt(data, &mut response),
        0x03 => handle_encrypt_aead(data, &mut response),
        0x04 => handle_decrypt_aead(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_encrypt(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 49 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&data[1..33]);
    nonce.copy_from_slice(&data[33..45]);
    let counter = u32::from_le_bytes([data[45], data[46], data[47], data[48]]);
    let len = if data.len() > 50 { u16::from_le_bytes([data[49], data[50]]) as usize } else { 0 };
    if len > 400 || data.len() < 51 + len {
        resp[0] = 0xFE;
        return;
    }
    resp[3..3 + len].copy_from_slice(&data[51..51 + len]);
    engine::encrypt(&key, &nonce, counter, &mut resp[3..3 + len]);
    resp[0] = 0x01;
    resp[1..3].copy_from_slice(&(len as u16).to_le_bytes());
}

fn handle_decrypt(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 49 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&data[1..33]);
    nonce.copy_from_slice(&data[33..45]);
    let counter = u32::from_le_bytes([data[45], data[46], data[47], data[48]]);
    let len = if data.len() > 50 { u16::from_le_bytes([data[49], data[50]]) as usize } else { 0 };
    if len > 400 || data.len() < 51 + len {
        resp[0] = 0xFE;
        return;
    }
    resp[3..3 + len].copy_from_slice(&data[51..51 + len]);
    engine::decrypt(&key, &nonce, counter, &mut resp[3..3 + len]);
    resp[0] = 0x01;
    resp[1..3].copy_from_slice(&(len as u16).to_le_bytes());
}

fn handle_encrypt_aead(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 47 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&data[1..33]);
    nonce.copy_from_slice(&data[33..45]);
    let len = u16::from_le_bytes([data[45], data[46]]) as usize;
    if len > 400 || data.len() < 47 + len {
        resp[0] = 0xFE;
        return;
    }
    resp[19..19 + len].copy_from_slice(&data[47..47 + len]);
    let mut tag = [0u8; 16];
    engine::encrypt_poly1305(&key, &nonce, &mut resp[19..19 + len], &mut tag);
    resp[0] = 0x01;
    resp[1..3].copy_from_slice(&(len as u16).to_le_bytes());
    resp[3..19].copy_from_slice(&tag);
}

fn handle_decrypt_aead(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 63 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    key.copy_from_slice(&data[1..33]);
    nonce.copy_from_slice(&data[33..45]);
    let len = u16::from_le_bytes([data[45], data[46]]) as usize;
    if len > 400 || data.len() < 63 + len {
        resp[0] = 0xFE;
        return;
    }
    tag.copy_from_slice(&data[47..63]);
    resp[1..1 + len].copy_from_slice(&data[63..63 + len]);
    if engine::decrypt_poly1305(&key, &nonce, &mut resp[1..1 + len], &tag) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x03;
    }
}

fn handle_get_stats(resp: &mut [u8; 512]) {
    let (ops, bytes) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&ops.to_le_bytes());
    resp[9..17].copy_from_slice(&bytes.to_le_bytes());
}
