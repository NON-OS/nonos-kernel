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

pub(super) fn process_request(data: &[u8]) -> [u8; 8192] {
    let mut response = [0u8; 8192];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_keygen(&mut response),
        0x02 => handle_sign(data, &mut response),
        0x03 => handle_verify(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_keygen(resp: &mut [u8; 8192]) {
    if let Some((pk, sk)) = engine::keygen() {
        resp[0] = 0x01;
        let pk_len = pk.len().min(1952);
        let sk_len = sk.len().min(4016);
        resp[1..1 + pk_len].copy_from_slice(&pk[..pk_len]);
        resp[1953..1953 + sk_len].copy_from_slice(&sk[..sk_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_sign(data: &[u8], resp: &mut [u8; 8192]) {
    if data.len() < 4019 {
        resp[0] = 0xFE;
        return;
    }
    let sk = &data[1..4017];
    let msg_len = u16::from_le_bytes([data[4017], data[4018]]) as usize;
    if data.len() < 4019 + msg_len {
        resp[0] = 0xFE;
        return;
    }
    let message = &data[4019..4019 + msg_len];
    if let Some(sig) = engine::sign(message, sk) {
        resp[0] = 0x01;
        let sig_len = sig.len().min(3293);
        resp[1..1 + sig_len].copy_from_slice(&sig[..sig_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_verify(data: &[u8], resp: &mut [u8; 8192]) {
    if data.len() < 5248 {
        resp[0] = 0xFE;
        return;
    }
    let pk = &data[1..1953];
    let sig = &data[1953..5246];
    let msg_len = u16::from_le_bytes([data[5246], data[5247]]) as usize;
    if data.len() < 5248 + msg_len {
        resp[0] = 0xFE;
        return;
    }
    let message = &data[5248..5248 + msg_len];
    let valid = engine::verify(message, sig, pk);
    resp[0] = 0x01;
    resp[1] = if valid { 1 } else { 0 };
}

fn handle_get_stats(resp: &mut [u8; 8192]) {
    let (keygens, signs, verifies) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&keygens.to_le_bytes());
    resp[9..17].copy_from_slice(&signs.to_le_bytes());
    resp[17..25].copy_from_slice(&verifies.to_le_bytes());
}
