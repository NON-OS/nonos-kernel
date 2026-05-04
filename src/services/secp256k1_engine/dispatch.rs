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
        0x01 => handle_keygen(&mut response),
        0x02 => handle_sign_ecdsa(data, &mut response),
        0x03 => handle_verify_ecdsa(data, &mut response),
        0x06 => handle_ecdh(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_keygen(resp: &mut [u8; 256]) {
    let mut privkey = [0u8; 32];
    let mut pubkey = [0u8; 33];
    engine::keygen(&mut privkey, &mut pubkey);
    resp[0] = 0x01;
    resp[1..33].copy_from_slice(&privkey);
    resp[33..66].copy_from_slice(&pubkey);
}

fn handle_sign_ecdsa(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 65 {
        resp[0] = 0xFE;
        return;
    }
    let mut privkey = [0u8; 32];
    let mut msg_hash = [0u8; 32];
    privkey.copy_from_slice(&data[1..33]);
    msg_hash.copy_from_slice(&data[33..65]);
    let mut signature = [0u8; 64];
    engine::sign_ecdsa(&privkey, &msg_hash, &mut signature);
    resp[0] = 0x01;
    resp[1..65].copy_from_slice(&signature);
}

fn handle_verify_ecdsa(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 130 {
        resp[0] = 0xFE;
        return;
    }
    let mut pubkey = [0u8; 33];
    let mut msg_hash = [0u8; 32];
    let mut signature = [0u8; 64];
    pubkey.copy_from_slice(&data[1..34]);
    msg_hash.copy_from_slice(&data[34..66]);
    signature.copy_from_slice(&data[66..130]);
    let valid = engine::verify_ecdsa(&pubkey, &msg_hash, &signature);
    resp[0] = 0x01;
    resp[1] = if valid { 1 } else { 0 };
}

fn handle_ecdh(data: &[u8], resp: &mut [u8; 256]) {
    if data.len() < 66 {
        resp[0] = 0xFE;
        return;
    }
    let mut privkey = [0u8; 32];
    let mut pubkey = [0u8; 33];
    privkey.copy_from_slice(&data[1..33]);
    pubkey.copy_from_slice(&data[33..66]);
    let mut shared = [0u8; 32];
    engine::ecdh(&privkey, &pubkey, &mut shared);
    resp[0] = 0x01;
    resp[1..33].copy_from_slice(&shared);
}

fn handle_get_stats(resp: &mut [u8; 256]) {
    let (signs, verifies, keygens, ecdhs) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&signs.to_le_bytes());
    resp[9..17].copy_from_slice(&verifies.to_le_bytes());
    resp[17..25].copy_from_slice(&keygens.to_le_bytes());
    resp[25..33].copy_from_slice(&ecdhs.to_le_bytes());
}
