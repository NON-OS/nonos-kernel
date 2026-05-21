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

use super::types::State;

impl State {
    pub fn write_snapshot(&self, out: &mut [u8]) -> usize {
        out[0..8].copy_from_slice(&self.probes.to_le_bytes());
        out[8..16].copy_from_slice(&self.csw_ok.to_le_bytes());
        out[16..24].copy_from_slice(&self.csw_failed.to_le_bytes());
        out[24..32].copy_from_slice(&self.phase_errors.to_le_bytes());
        out[32..36].copy_from_slice(&(self.binding_count as u32).to_le_bytes());
        out[36..44].copy_from_slice(&self.residue_bytes.to_le_bytes());
        out[44..48].copy_from_slice(&self.last_tag.to_le_bytes());
        48
    }
}
