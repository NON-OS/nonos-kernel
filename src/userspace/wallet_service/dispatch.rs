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

use super::wallet;

pub(super) fn process_request(data: &[u8]) -> [u8; 128] {
    let mut response = [0u8; 128];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_create(data, &mut response),
        0x02 => handle_get(data, &mut response),
        0x03 => handle_delete(data, &mut response),
        0x04 => handle_count(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_create(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 38 {
        resp[0] = 0xFE;
        return;
    }
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&data[1..34]);
    let chain_id = u32::from_le_bytes([data[34], data[35], data[36], data[37]]);
    let id = wallet::create_account(&pubkey, chain_id);
    if id > 0 {
        resp[0] = 0x01;
        resp[1..5].copy_from_slice(&id.to_le_bytes());
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
    if let Some(account) = wallet::get_account(id) {
        resp[0] = 0x01;
        resp[1..5].copy_from_slice(&account.id.to_le_bytes());
        resp[5..38].copy_from_slice(&account.pubkey);
        resp[38..58].copy_from_slice(&account.address);
        resp[58..62].copy_from_slice(&account.chain_id.to_le_bytes());
    } else {
        resp[0] = 0x02;
    }
}

fn handle_delete(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 5 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if wallet::delete_account(id) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_count(resp: &mut [u8; 128]) {
    resp[0] = 0x01;
    resp[1] = wallet::account_count();
}
