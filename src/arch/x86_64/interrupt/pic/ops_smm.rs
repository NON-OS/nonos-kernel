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

use super::constants::*;
use super::error::{PicError, PicResult};
use super::io::outb;
use super::state::is_initialized;
use crate::memory::proof::{self, CapTag};

pub unsafe fn enable_smm() -> PicResult<()> {
    unsafe {
        if !is_initialized() {
            return Err(PicError::NotInitialized);
        }
        outb(PIC1_CMD, 0x68);
        outb(PIC2_CMD, 0x68);
        proof::audit_phys_alloc(0x8259_0004, 1, CapTag::KERNEL);
        Ok(())
    }
}

pub unsafe fn disable_smm() -> PicResult<()> {
    unsafe {
        if !is_initialized() {
            return Err(PicError::NotInitialized);
        }
        outb(PIC1_CMD, 0x48);
        outb(PIC2_CMD, 0x48);
        proof::audit_phys_alloc(0x8259_0005, 0, CapTag::KERNEL);
        Ok(())
    }
}
