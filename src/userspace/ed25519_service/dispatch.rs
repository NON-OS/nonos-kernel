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
        0x01 => handle_keygen(data, &mut response),
        0x02 => handle_sign(data, &mut response),
        0x03 => handle_verify(data, &mut response),
        0x04 => handle_pubkey_from_private(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_keygen(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 33 {
        resp[0] = 0xFE;
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[1..33]);
    let mut pubkey = [0u8; 32];
    let mut privkey = [0u8; 64];
    engine::generate_keypair(&seed, &mut pubkey, &mut privkey);
    resp[0] = 0x01;
    resp[1..33].copy_from_slice(&pubkey);
    resp[33..97].copy_from_slice(&privkey);
}

fn handle_sign(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 67 {
        resp[0] = 0xFE;
        return;
    }
    let mut privkey = [0u8; 64];
    privkey.copy_from_slice(&data[1..65]);
    let len = u16::from_le_bytes([data[65], data[66]]) as usize;
    if len > 150 || data.len() < 67 + len {
        resp[0] = 0xFE;
        return;
    }
    let mut signature = [0u8; 64];
    engine::sign(&privkey, &data[67..67 + len], &mut signature);
    resp[0] = 0x01;
    resp[1..65].copy_from_slice(&signature);
}

fn handle_verify(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 99 {
        resp[0] = 0xFE;
        return;
    }
    let mut pubkey = [0u8; 32];
    let mut signature = [0u8; 64];
    pubkey.copy_from_slice(&data[1..33]);
    signature.copy_from_slice(&data[33..97]);
    let len = u16::from_le_bytes([data[97], data[98]]) as usize;
    if len > 150 || data.len() < 99 + len {
        resp[0] = 0xFE;
        return;
    }
    let valid = engine::verify(&pubkey, &data[99..99 + len], &signature);
    resp[0] = 0x01;
    resp[1] = if valid { 1 } else { 0 };
}

fn handle_pubkey_from_private(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 65 {
        resp[0] = 0xFE;
        return;
    }
    let mut privkey = [0u8; 64];
    privkey.copy_from_slice(&data[1..65]);
    let mut pubkey = [0u8; 32];
    engine::public_key_from_private(&privkey, &mut pubkey);
    resp[0] = 0x01;
    resp[1..33].copy_from_slice(&pubkey);
}

fn handle_get_stats(resp: &mut [u8; 256]) {
    let (signs, verifies, keygens) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&signs.to_le_bytes());
    resp[9..17].copy_from_slice(&verifies.to_le_bytes());
    resp[17..25].copy_from_slice(&keygens.to_le_bytes());
}
