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

use super::vectors;

pub use crate::arch::x86_64::gdt::{
    DF_IST_INDEX as DOUBLE_FAULT_IST_INDEX, MC_IST_INDEX as MACHINE_CHECK_IST_INDEX,
    NMI_IST_INDEX, PF_IST_INDEX as PAGE_FAULT_IST_INDEX,
};

pub const TIMER_INTERRUPT_ID: u8 = vectors::VECTOR_TIMER;
pub const KEYBOARD_INTERRUPT_ID: u8 = vectors::VECTOR_KEYBOARD;
pub const MOUSE_INTERRUPT_ID: u8 = vectors::VECTOR_MOUSE;
pub const SYSCALL_INTERRUPT_ID: u8 = vectors::VECTOR_SYSCALL;
