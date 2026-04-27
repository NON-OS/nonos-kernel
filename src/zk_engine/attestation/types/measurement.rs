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

use super::memory_layout::MemoryLayout;
use super::module_hash::ModuleHash;
use crate::crypto::hash::blake3_hash;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct KernelMeasurement {
    pub code_hash: [u8; 32],
    pub data_hash: [u8; 32],
    pub config_hash: [u8; 32],
    pub memory_layout: MemoryLayout,
    pub module_hashes: Vec<ModuleHash>,
    pub integrity_hash: [u8; 32],
}

impl KernelMeasurement {
    pub fn new() -> Self {
        Self {
            code_hash: [0; 32],
            data_hash: [0; 32],
            config_hash: [0; 32],
            memory_layout: MemoryLayout::default(),
            module_hashes: Vec::new(),
            integrity_hash: [0; 32],
        }
    }

    pub fn compute_integrity_hash(&self) -> [u8; 32] {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&self.code_hash);
        hasher_input.extend_from_slice(&self.data_hash);
        hasher_input.extend_from_slice(&self.config_hash);
        hasher_input.extend_from_slice(&self.memory_layout.to_bytes());

        for module in &self.module_hashes {
            hasher_input.extend_from_slice(&module.hash);
        }

        blake3_hash(&hasher_input)
    }
}
