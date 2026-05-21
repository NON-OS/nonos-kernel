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

use super::constants::{MSR_AMD_SYSCFG, SYSCFG_MEM_ENCRYPT_BIT};
use super::rdmsr::rdmsr;
use crate::memory::encryption::error::{MemEncryptionError, MemEncryptionResult};
use crate::memory::encryption::types::EncryptionCapability;

pub fn init_sme(cap: &EncryptionCapability) -> MemEncryptionResult<()> {
    if !cap.sme_supported {
        return Err(MemEncryptionError::NotSupported);
    }
    let syscfg = rdmsr(MSR_AMD_SYSCFG);
    if (syscfg & SYSCFG_MEM_ENCRYPT_BIT) == 0 {
        return Err(MemEncryptionError::NotSupported);
    }
    Ok(())
}
