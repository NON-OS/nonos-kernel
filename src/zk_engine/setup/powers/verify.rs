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

use super::types::Powers;
use crate::zk_engine::groth16::Pairing;
use crate::zk_engine::ZKError;

impl Powers {
    pub fn verify_powers(&self) -> Result<bool, ZKError> {
        if self.tau_g1.len() < 2 || self.tau_g2.len() < 2 {
            return Ok(false);
        }

        let pairing1 = Pairing::compute(&self.tau_g1[0], &self.tau_g2[1]);
        let pairing2 = Pairing::compute(&self.tau_g1[1], &self.tau_g2[0]);

        Ok(pairing1.equals(&pairing2))
    }
}
