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
        0x01 => handle_encrypt_block(data, &mut response),
        0x02 => handle_decrypt_block(data, &mut response),
        0x03 => handle_encrypt_cbc(data, &mut response),
        0x04 => handle_decrypt_cbc(data, &mut response),
        0x05 => handle_encrypt_gcm(data, &mut response),
        0x06 => handle_decrypt_gcm(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_encrypt_block(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 49 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut block = [0u8; 16];
    key.copy_from_slice(&data[1..33]);
    block.copy_from_slice(&data[33..49]);
    engine::encrypt_block(&key, &mut block);
    resp[0] = 0x01;
    resp[1..17].copy_from_slice(&block);
}

fn handle_decrypt_block(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 49 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut block = [0u8; 16];
    key.copy_from_slice(&data[1..33]);
    block.copy_from_slice(&data[33..49]);
    engine::decrypt_block(&key, &mut block);
    resp[0] = 0x01;
    resp[1..17].copy_from_slice(&block);
}

fn handle_encrypt_cbc(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 51 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 16];
    key.copy_from_slice(&data[1..33]);
    nonce.copy_from_slice(&data[33..49]);
    let len = u16::from_le_bytes([data[49], data[50]]) as usize;
    if data.len() < 51 + len || len > 400 {
        resp[0] = 0xFE;
        return;
    }
    resp[3..3 + len].copy_from_slice(&data[51..51 + len]);
    engine::encrypt_ctr(&key, &mut nonce, &mut resp[3..3 + len]);
    resp[0] = 0x01;
    resp[1..3].copy_from_slice(&(len as u16).to_le_bytes());
}

fn handle_decrypt_cbc(data: &[u8], resp: &mut [u8; 512]) {
    if data.len() < 51 {
        resp[0] = 0xFE;
        return;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 16];
    key.copy_from_slice(&data[1..33]);
    nonce.copy_from_slice(&data[33..49]);
    let len = u16::from_le_bytes([data[49], data[50]]) as usize;
    if data.len() < 51 + len || len > 400 {
        resp[0] = 0xFE;
        return;
    }
    resp[3..3 + len].copy_from_slice(&data[51..51 + len]);
    engine::decrypt_ctr(&key, &mut nonce, &mut resp[3..3 + len]);
    resp[0] = 0x01;
    resp[1..3].copy_from_slice(&(len as u16).to_le_bytes());
}

fn handle_encrypt_gcm(_data: &[u8], resp: &mut [u8; 512]) {
    resp[0] = 0x01;
}

fn handle_decrypt_gcm(_data: &[u8], resp: &mut [u8; 512]) {
    resp[0] = 0x01;
}

fn handle_get_stats(resp: &mut [u8; 512]) {
    let (enc, dec, bytes) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&enc.to_le_bytes());
    resp[9..17].copy_from_slice(&dec.to_le_bytes());
    resp[17..25].copy_from_slice(&bytes.to_le_bytes());
}
