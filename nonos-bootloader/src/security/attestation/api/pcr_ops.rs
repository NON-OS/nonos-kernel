// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::state::ATTESTATION_STATE;
use crate::security::attestation::pcr::PcrIndex;

pub fn extend_pcr(index: PcrIndex, data: &[u8]) {
    let mut state = ATTESTATION_STATE.lock();
    state.extend_pcr(index, data);
}

pub fn extend_pcr_hash(index: PcrIndex, hash: &[u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.extend_pcr_hash(index, hash);
}

pub fn get_boot_measurement() -> [u8; 32] {
    let state = ATTESTATION_STATE.lock();
    state.compute_composite_hash()
}
