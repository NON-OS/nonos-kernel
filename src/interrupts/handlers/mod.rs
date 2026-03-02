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

pub mod exceptions;
pub mod irq;

pub use exceptions::{
    alignment_check, bound_range_exceeded, breakpoint, debug, device_not_available, divide_error,
    double_fault, general_protection_fault, invalid_opcode, invalid_tss, machine_check, nmi,
    overflow, page_fault, segment_not_present, simd_floating_point, stack_segment_fault,
    virtualization, x87_floating_point, ExceptionContext, PageFaultContext, PageFaultErrorCode,
};

pub use irq::{keyboard, mouse, syscall, timer};
