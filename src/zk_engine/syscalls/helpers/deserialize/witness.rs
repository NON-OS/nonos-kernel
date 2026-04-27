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

use crate::zk_engine::syscalls::params::MAX_WITNESS_SIZE;
use alloc::vec::Vec;

pub fn deserialize_witness(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if data.len() < 4 {
        return Err("Witness data too short");
    }

    let mut offset = 0;
    let num_witnesses = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    offset += 4;

    if num_witnesses > MAX_WITNESS_SIZE / 32 {
        return Err("Too many witnesses");
    }

    let mut witnesses = Vec::with_capacity(num_witnesses);

    for _ in 0..num_witnesses {
        if offset + 4 > data.len() {
            return Err("Truncated witness data");
        }

        let witness_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + witness_len > data.len() {
            return Err("Truncated witness data");
        }

        let witness = data[offset..offset + witness_len].to_vec();
        witnesses.push(witness);
        offset += witness_len;
    }

    Ok(witnesses)
}

pub fn deserialize_public_inputs(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    deserialize_witness(data)
}
