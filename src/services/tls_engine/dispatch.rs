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

use super::session;

pub(super) fn process_request(data: &[u8]) -> [u8; 128] {
    let mut response = [0u8; 128];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_create(&mut response),
        0x02 => handle_set_randoms(data, &mut response),
        0x03 => handle_set_secret(data, &mut response),
        0x04 => handle_destroy(data, &mut response),
        0x05 => handle_count(&mut response),
        0x06 => handle_set_cipher_suite(data, &mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_create(resp: &mut [u8; 128]) {
    let id = session::create_session();
    if id > 0 {
        resp[0] = 0x01;
        resp[1..5].copy_from_slice(&id.to_le_bytes());
    } else {
        resp[0] = 0x02;
    }
}

fn handle_set_randoms(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 69 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let mut client = [0u8; 32];
    let mut server = [0u8; 32];
    client.copy_from_slice(&data[5..37]);
    server.copy_from_slice(&data[37..69]);
    if session::set_randoms(id, &client, &server) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_set_secret(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 53 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let mut secret = [0u8; 48];
    secret.copy_from_slice(&data[5..53]);
    if session::set_master_secret(id, &secret) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_destroy(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 5 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if session::destroy_session(id) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}

fn handle_count(resp: &mut [u8; 128]) {
    resp[0] = 0x01;
    resp[1] = session::session_count();
}

fn handle_set_cipher_suite(data: &[u8], resp: &mut [u8; 128]) {
    if data.len() < 7 {
        resp[0] = 0xFE;
        return;
    }
    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let suite = u16::from_le_bytes([data[5], data[6]]);
    if session::set_cipher_suite(id, suite) {
        resp[0] = 0x01;
    } else {
        resp[0] = 0x02;
    }
}
