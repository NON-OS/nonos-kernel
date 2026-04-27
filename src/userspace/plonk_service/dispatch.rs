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
use alloc::vec::Vec;

pub(super) fn process_request(data: &[u8]) -> [u8; 1024] {
    let mut response = [0u8; 1024];
    if data.is_empty() {
        return response;
    }
    match data[0] {
        0x01 => handle_prove(data, &mut response),
        0x02 => handle_verify(data, &mut response),
        0x10 => handle_get_stats(&mut response),
        _ => {
            response[0] = 0xFF;
        }
    }
    response
}

fn handle_prove(data: &[u8], resp: &mut [u8; 1024]) {
    if data.len() < 9 {
        resp[0] = 0xFE;
        return;
    }
    let circuit_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let witness_count = u16::from_le_bytes([data[5], data[6]]) as usize;
    let inputs_count = u16::from_le_bytes([data[7], data[8]]) as usize;
    let mut offset = 9usize;
    let witness = parse_vec_vec(data, &mut offset, witness_count);
    let public_inputs = parse_vec_vec(data, &mut offset, inputs_count);
    if let Some(proof) = engine::generate_proof(circuit_id, witness, public_inputs) {
        let len = proof.len().min(1000);
        resp[0] = 0x01;
        resp[1..3].copy_from_slice(&(len as u16).to_le_bytes());
        resp[3..3 + len].copy_from_slice(&proof[..len]);
    } else {
        resp[0] = 0x02;
    }
}

fn parse_vec_vec(data: &[u8], offset: &mut usize, count: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if *offset + 2 > data.len() {
            break;
        }
        let len = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as usize;
        *offset += 2;
        if *offset + len > data.len() {
            break;
        }
        result.push(data[*offset..*offset + len].to_vec());
        *offset += len;
    }
    result
}

fn handle_verify(data: &[u8], resp: &mut [u8; 1024]) {
    if data.len() < 3 {
        resp[0] = 0xFE;
        return;
    }
    let proof_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    if data.len() < 3 + proof_len {
        resp[0] = 0xFE;
        return;
    }
    let proof_data = &data[3..3 + proof_len];
    let valid = engine::verify_proof(proof_data);
    resp[0] = 0x01;
    resp[1] = if valid { 1 } else { 0 };
}

fn handle_get_stats(resp: &mut [u8; 1024]) {
    let (generated, verified) = engine::get_stats();
    resp[0] = 0x01;
    resp[1..9].copy_from_slice(&generated.to_le_bytes());
    resp[9..17].copy_from_slice(&verified.to_le_bytes());
}
