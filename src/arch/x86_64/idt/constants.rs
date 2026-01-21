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

pub const IDT_ENTRIES: usize = 256;
pub const KERNEL_CS: u16 = 0x08;
// Gate types
pub const GATE_INTERRUPT: u8 = 0x0E;
pub const GATE_TRAP: u8 = 0x0F;
// Privilege levels
pub const DPL_KERNEL: u8 = 0;
pub const DPL_USER: u8 = 3;
// Flags
pub const PRESENT: u8 = 1 << 7;
// Exception vector numbers
pub const VEC_DIVIDE_ERROR: u8 = 0;
pub const VEC_DEBUG: u8 = 1;
pub const VEC_NMI: u8 = 2;
pub const VEC_BREAKPOINT: u8 = 3;
pub const VEC_OVERFLOW: u8 = 4;
pub const VEC_BOUND_RANGE: u8 = 5;
pub const VEC_INVALID_OPCODE: u8 = 6;
pub const VEC_DEVICE_NOT_AVAILABLE: u8 = 7;
pub const VEC_DOUBLE_FAULT: u8 = 8;
pub const VEC_COPROCESSOR_SEGMENT: u8 = 9;
pub const VEC_INVALID_TSS: u8 = 10;
pub const VEC_SEGMENT_NOT_PRESENT: u8 = 11;
pub const VEC_STACK_SEGMENT: u8 = 12;
pub const VEC_GENERAL_PROTECTION: u8 = 13;
pub const VEC_PAGE_FAULT: u8 = 14;
pub const VEC_RESERVED_15: u8 = 15;
pub const VEC_X87_FP: u8 = 16;
pub const VEC_ALIGNMENT_CHECK: u8 = 17;
pub const VEC_MACHINE_CHECK: u8 = 18;
pub const VEC_SIMD_FP: u8 = 19;
pub const VEC_VIRTUALIZATION: u8 = 20;
pub const VEC_CONTROL_PROTECTION: u8 = 21;
// Hardware interrupt base (after remapping PIC)
pub const IRQ_BASE: u8 = 32;
// IST indices (matching GDT)
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
pub const IST_DEBUG: u8 = 4;
pub const IST_PAGE_FAULT: u8 = 5;
pub const IST_GP: u8 = 6;
// PIC ports
pub(crate) const PIC1_COMMAND: u16 = 0x20;
pub(crate) const PIC1_DATA: u16 = 0x21;
pub(crate) const PIC2_COMMAND: u16 = 0xA0;
pub(crate) const PIC2_DATA: u16 = 0xA1;
// PIC commands
pub(crate) const PIC_EOI: u8 = 0x20;
pub(crate) const ICW1_INIT: u8 = 0x11;
pub(crate) const ICW4_8086: u8 = 0x01;
