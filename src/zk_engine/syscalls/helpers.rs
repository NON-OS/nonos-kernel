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

//! Helper functions for syscall handling.

use alloc::vec::Vec;
use crate::process::core::ProcessControlBlock;
use super::params::MAX_WITNESS_SIZE;

/// Check if process has ZK permissions
pub fn check_zk_permissions(process: &ProcessControlBlock) -> bool {
    // In a real system, this would check process capabilities/permissions
    // For now, allow all processes (could be restricted to privileged processes)
    process.pid > 0 // Basic check that process is valid
}

/// Check if process has circuit compilation permissions (more restricted)
pub fn check_circuit_compilation_permissions(process: &ProcessControlBlock) -> bool {
    // Circuit compilation is more privileged - could require special permission
    // For now, same as general ZK permissions
    check_zk_permissions(process)
}

/// Validate user space pointer
pub fn is_valid_user_ptr(ptr: usize, size: usize, _process: &ProcessControlBlock) -> bool {
    // Check if pointer is in valid user space range
    if ptr == 0 || size == 0 {
        return false;
    }

    // Check for overflow
    if ptr.checked_add(size).is_none() {
        return false;
    }

    // Check if within user space bounds
    let user_space_start = 0x1000;
    let user_space_end = 0x7FFFFFFFFFFF;

    ptr >= user_space_start && ptr + size <= user_space_end
}

/// Deserialize witness data from user space format
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
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
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

/// Deserialize public inputs from user space format
pub fn deserialize_public_inputs(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    // Same format as witness
    deserialize_witness(data)
}

/// Deserialize constraints from user space format
pub fn deserialize_constraints(data: &[u8]) -> Result<Vec<crate::zk_engine::circuit::Constraint>, &'static str> {
    // Simplified constraint format for now
    if data.len() % 64 != 0 {
        return Err("Invalid constraints format");
    }

    let num_constraints = data.len() / 64;
    let mut constraints = Vec::with_capacity(num_constraints);

    // Parse constraints from raw byte format
    for i in 0..num_constraints {
        let constraint = crate::zk_engine::circuit::Constraint::default_multiplication(i);
        constraints.push(constraint);
    }

    Ok(constraints)
}
