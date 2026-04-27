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

use super::super::types::KernelAttestation;
use super::types::AttestationManager;
use crate::zk_engine::ZKError;
use core::ptr::addr_of_mut;

static mut GLOBAL_ATTESTATION_MANAGER: Option<AttestationManager> = None;

pub fn init_attestation_manager() -> Result<(), ZKError> {
    let manager = AttestationManager::new()?;
    unsafe {
        *addr_of_mut!(GLOBAL_ATTESTATION_MANAGER) = Some(manager);
    }
    Ok(())
}

pub fn get_attestation_manager() -> Option<&'static mut AttestationManager> {
    unsafe { (*addr_of_mut!(GLOBAL_ATTESTATION_MANAGER)).as_mut() }
}

pub fn generate_system_attestation() -> Result<KernelAttestation, ZKError> {
    let manager = get_attestation_manager().ok_or(ZKError::NotInitialized)?;
    manager.generate_attestation()
}
