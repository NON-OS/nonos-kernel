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
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl KernelMeasurement {
    pub fn to_field_elements(&self) -> Result<Vec<FieldElement>, ZKError> {
        let mut elements = Vec::new();
        elements.push(FieldElement::from_bytes(&self.code_hash)?);
        elements.push(FieldElement::from_bytes(&self.data_hash)?);
        elements.push(FieldElement::from_bytes(&self.config_hash)?);
        elements.push(FieldElement::from_bytes(&self.integrity_hash)?);
        Ok(elements)
    }

    pub fn to_witness(&self) -> Result<Vec<Vec<u8>>, ZKError> {
        let mut witness = Vec::new();
        witness.push(self.code_hash.to_vec());
        witness.push(self.data_hash.to_vec());
        witness.push(self.config_hash.to_vec());
        witness.push(self.integrity_hash.to_vec());
        Ok(witness)
    }
}
