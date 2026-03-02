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

use x86_64::structures::idt::InterruptStackFrame;

#[derive(Debug, Clone, Copy)]
pub struct ExceptionContext {
    pub instruction_pointer: u64,
    pub code_segment: u16,
    pub stack_pointer: u64,
    pub stack_segment: u16,
    pub cpu_flags: u64,
}

impl ExceptionContext {
    pub fn from_frame(frame: &InterruptStackFrame) -> Self {
        Self {
            instruction_pointer: frame.instruction_pointer.as_u64(),
            code_segment: frame.code_segment as u16,
            stack_pointer: frame.stack_pointer.as_u64(),
            stack_segment: frame.stack_segment as u16,
            cpu_flags: frame.cpu_flags,
        }
    }

    pub fn is_user_mode(&self) -> bool {
        (self.code_segment & 0x3) == 3
    }

    pub fn is_kernel_mode(&self) -> bool {
        (self.code_segment & 0x3) == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageFaultContext {
    pub exception: ExceptionContext,
    pub accessed_address: u64,
    pub error_code: PageFaultErrorCode,
}

#[derive(Debug, Clone, Copy)]
pub struct PageFaultErrorCode {
    bits: u64,
}

impl PageFaultErrorCode {
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    pub const fn bits(&self) -> u64 {
        self.bits
    }

    pub const fn is_protection_violation(&self) -> bool {
        (self.bits & 0x01) != 0
    }

    pub const fn is_write(&self) -> bool {
        (self.bits & 0x02) != 0
    }

    pub const fn is_user_mode(&self) -> bool {
        (self.bits & 0x04) != 0
    }

    pub const fn is_reserved_write(&self) -> bool {
        (self.bits & 0x08) != 0
    }

    pub const fn is_instruction_fetch(&self) -> bool {
        (self.bits & 0x10) != 0
    }

    pub const fn is_protection_key(&self) -> bool {
        (self.bits & 0x20) != 0
    }

    pub const fn is_shadow_stack(&self) -> bool {
        (self.bits & 0x40) != 0
    }

    pub const fn is_sgx(&self) -> bool {
        (self.bits & 0x8000) != 0
    }
}

pub(super) fn log_exception(name: &str, ctx: &ExceptionContext) {
    crate::log::logger::log_critical(&alloc::format!(
        "{}: rip={:#x} cs={:#x} rsp={:#x} ss={:#x} rflags={:#x}",
        name,
        ctx.instruction_pointer,
        ctx.code_segment,
        ctx.stack_pointer,
        ctx.stack_segment,
        ctx.cpu_flags
    ));
}

pub(super) fn log_exception_with_code(name: &str, ctx: &ExceptionContext, code: u64) {
    crate::log::logger::log_critical(&alloc::format!(
        "{}: err={:#x} rip={:#x} cs={:#x} rsp={:#x} rflags={:#x}",
        name,
        code,
        ctx.instruction_pointer,
        ctx.code_segment,
        ctx.stack_pointer,
        ctx.cpu_flags
    ));
}

pub(super) fn log_page_fault(ctx: &PageFaultContext) {
    crate::log::logger::log_critical(&alloc::format!(
        "PAGE FAULT: addr={:#x} err={:#x} rip={:#x} rsp={:#x} rflags={:#x}",
        ctx.accessed_address,
        ctx.error_code.bits(),
        ctx.exception.instruction_pointer,
        ctx.exception.stack_pointer,
        ctx.exception.cpu_flags
    ));
}
