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

use super::super::constants::{CR0_PG, CR4_PAE, EFER_LMA, MSR_EFER};
use super::super::cpu_ops::{read_cr0, read_cr3, read_cr4, rdmsr};
use super::super::error::BootError;

pub unsafe fn validate_memory() -> Result<(), BootError> {
    let cr3 = read_cr3();
    if cr3 == 0 {
        return Err(BootError::InvalidPageTable);
    }

    let cr0 = read_cr0();
    if cr0 & CR0_PG == 0 {
        return Err(BootError::PagingNotEnabled);
    }

    let cr4 = read_cr4();
    if cr4 & CR4_PAE == 0 {
        return Err(BootError::PaeNotEnabled);
    }

    let efer = rdmsr(MSR_EFER);
    if efer & EFER_LMA == 0 {
        return Err(BootError::LongModeNotActive);
    }

    Ok(())
}
