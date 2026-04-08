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

use crate::memory::proof::{self, CapTag};
use super::constants::*;
use super::error::{PicError, PicResult};
use super::state::{is_initialized, is_disabled};
use super::mask::mask_all_internal;
use super::ops_reinit::reinit_with_icw4;

pub unsafe fn enable_aeoi() -> PicResult<()> {
    unsafe {
        if !is_initialized() { return Err(PicError::NotInitialized); }
        if is_disabled() { return Err(PicError::Disabled); }
        let icw4 = ICW4_8086 | ICW4_AEOI;
        reinit_with_icw4(0x20, 0x28, icw4, icw4);
        proof::audit_phys_alloc(0x8259_0002, 1, CapTag::KERNEL);
        Ok(())
    }
}

pub unsafe fn disable_aeoi() -> PicResult<()> {
    unsafe {
        if !is_initialized() { return Err(PicError::NotInitialized); }
        reinit_with_icw4(0x20, 0x28, ICW4_8086, ICW4_8086);
        mask_all_internal();
        proof::audit_phys_alloc(0x8259_0003, 0, CapTag::KERNEL);
        Ok(())
    }
}
