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

use super::measurement::KernelMeasurement;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl KernelMeasurement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.code_hash);
        data.extend_from_slice(&self.data_hash);
        data.extend_from_slice(&self.config_hash);
        data.extend_from_slice(&self.memory_layout.to_bytes());
        data.extend_from_slice(&self.integrity_hash);

        data.extend_from_slice(&(self.module_hashes.len() as u32).to_le_bytes());
        for module in &self.module_hashes {
            data.extend_from_slice(module.name.as_bytes());
            data.extend_from_slice(&[0]);
            data.extend_from_slice(&module.hash);
            data.extend_from_slice(&module.address.as_u64().to_le_bytes());
            data.extend_from_slice(&module.size.to_le_bytes());
        }

        data
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 96 {
            return Err(ZKError::InvalidFormat);
        }

        let mut measurement = Self::new();
        let mut offset = 0;

        measurement.code_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        measurement.data_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        measurement.config_hash.copy_from_slice(&data[offset..offset + 32]);

        Ok(measurement)
    }
}
