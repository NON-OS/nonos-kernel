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

pub fn set_kernel_measurement(hash: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_kernel_hash(hash);
}

pub fn set_bootloader_measurement(hash: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_bootloader_hash(hash);
}

pub fn set_zk_attestation(verified: bool, program_hash: [u8; 32], commitment: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_zk_verified(verified, program_hash, commitment);
}

pub fn set_signature_attestation(verified: bool) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_signature_verified(verified);
}
