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

use super::super::super::error::WifiError;
use super::super::crypto::prf_sha1;
use super::types::WpaContext;
use alloc::vec::Vec;

impl WpaContext {
    pub fn generate_snonce(&mut self) -> Result<(), WifiError> {
        crate::crypto::fill_random_bytes(&mut self.snonce);
        Ok(())
    }

    pub(super) fn derive_ptk(&mut self) -> Result<(), WifiError> {
        let mut data = Vec::with_capacity(76);

        if self.aa < self.spa {
            data.extend_from_slice(&self.aa);
            data.extend_from_slice(&self.spa);
        } else {
            data.extend_from_slice(&self.spa);
            data.extend_from_slice(&self.aa);
        }

        if self.anonce < self.snonce {
            data.extend_from_slice(&self.anonce);
            data.extend_from_slice(&self.snonce);
        } else {
            data.extend_from_slice(&self.snonce);
            data.extend_from_slice(&self.anonce);
        }

        prf_sha1(&self.pmk, b"Pairwise key expansion", &data, &mut self.ptk)?;

        Ok(())
    }
}
