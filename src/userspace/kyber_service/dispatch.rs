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

pub(super) fn process_request(data: &[u8]) -> [u8; 4096] {
    let mut response = [0u8; 4096];
    if data.is_empty() {
        return response;
    }

    match data[0] {
        0x01 => handle_keygen_768(&mut response),
        0x02 => handle_encaps_768(data, &mut response),
        0x03 => handle_decaps_768(data, &mut response),
        0x04 => handle_keygen_1024(&mut response),
        0x05 => handle_encaps_1024(data, &mut response),
        0x06 => handle_decaps_1024(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_keygen_768(resp: &mut [u8; 4096]) {
    if let Some((pk, sk)) = engine::keygen_768() {
        resp[0] = 0x01;
        let pk_len = pk.len().min(1184);
        let sk_len = sk.len().min(2400);
        resp[1..1 + pk_len].copy_from_slice(&pk[..pk_len]);
        resp[1185..1185 + sk_len].copy_from_slice(&sk[..sk_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_encaps_768(data: &[u8], resp: &mut [u8; 4096]) {
    if data.len() < 1185 {
        resp[0] = 0xFE;
        return;
    }
    let pk = &data[1..1185];
    if let Some((ct, ss)) = engine::encapsulate_768(pk) {
        resp[0] = 0x01;
        let ct_len = ct.len().min(1088);
        let ss_len = ss.len().min(32);
        resp[1..1 + ct_len].copy_from_slice(&ct[..ct_len]);
        resp[1089..1089 + ss_len].copy_from_slice(&ss[..ss_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_decaps_768(data: &[u8], resp: &mut [u8; 4096]) {
    if data.len() < 3489 {
        resp[0] = 0xFE;
        return;
    }
    let ct = &data[1..1089];
    let sk = &data[1089..3489];
    if let Some(ss) = engine::decapsulate_768(ct, sk) {
        resp[0] = 0x01;
        let ss_len = ss.len().min(32);
        resp[1..1 + ss_len].copy_from_slice(&ss[..ss_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_keygen_1024(resp: &mut [u8; 4096]) {
    if let Some((pk, sk)) = engine::keygen_1024() {
        resp[0] = 0x01;
        let pk_len = pk.len().min(1568);
        let sk_len = sk.len().min(3168);
        resp[1..1 + pk_len].copy_from_slice(&pk[..pk_len]);
        resp[1569..1569 + sk_len].copy_from_slice(&sk[..sk_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_encaps_1024(data: &[u8], resp: &mut [u8; 4096]) {
    if data.len() < 1569 {
        resp[0] = 0xFE;
        return;
    }
    let pk = &data[1..1569];
    if let Some((ct, ss)) = engine::encapsulate_1024(pk) {
        resp[0] = 0x01;
        let ct_len = ct.len().min(1568);
        let ss_len = ss.len().min(32);
        resp[1..1 + ct_len].copy_from_slice(&ct[..ct_len]);
        resp[1569..1569 + ss_len].copy_from_slice(&ss[..ss_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_decaps_1024(data: &[u8], resp: &mut [u8; 4096]) {
    if data.len() < 4737 {
        resp[0] = 0xFE;
        return;
    }
    let ct = &data[1..1569];
    let sk = &data[1569..4737];
    if let Some(ss) = engine::decapsulate_1024(ct, sk) {
        resp[0] = 0x01;
        let ss_len = ss.len().min(32);
        resp[1..1 + ss_len].copy_from_slice(&ss[..ss_len]);
    } else {
        resp[0] = 0x02;
    }
}

fn handle_get_stats(resp: &mut [u8; 4096]) {
    let (keygens, encaps, decaps) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&keygens.to_le_bytes());
    resp[9..17].copy_from_slice(&encaps.to_le_bytes());
    resp[17..25].copy_from_slice(&decaps.to_le_bytes());
}
