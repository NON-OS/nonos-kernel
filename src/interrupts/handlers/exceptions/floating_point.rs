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

use super::context::ExceptionContext;
use crate::interrupts::stats;

#[derive(Debug, Clone, Copy)]
pub(crate) struct X87Status {
    bits: u16,
}

impl X87Status {
    pub(crate) const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    pub(crate) const fn invalid_operation(&self) -> bool {
        (self.bits & 0x01) != 0
    }

    pub(crate) const fn denormalized_operand(&self) -> bool {
        (self.bits & 0x02) != 0
    }

    pub(crate) const fn divide_by_zero(&self) -> bool {
        (self.bits & 0x04) != 0
    }

    pub(crate) const fn overflow(&self) -> bool {
        (self.bits & 0x08) != 0
    }

    pub(crate) const fn underflow(&self) -> bool {
        (self.bits & 0x10) != 0
    }

    pub(crate) const fn precision(&self) -> bool {
        (self.bits & 0x20) != 0
    }

    pub(crate) const fn stack_fault(&self) -> bool {
        (self.bits & 0x40) != 0
    }
}

pub fn handle_x87(frame: InterruptStackFrame) {
    let ctx = ExceptionContext::from_frame(&frame);
    stats::increment_exceptions();

    let status = read_x87_status();
    log_x87_exception(&ctx, &status);
    clear_x87_exception();
}

pub fn handle_simd(frame: InterruptStackFrame) {
    let ctx = ExceptionContext::from_frame(&frame);
    stats::increment_exceptions();

    let mxcsr = read_mxcsr();
    log_simd_exception(&ctx, mxcsr);
    clear_simd_exception();
}

fn read_x87_status() -> X87Status {
    let status: u16;
    // SAFETY: Reading x87 FPU status word
    unsafe {
        core::arch::asm!(
            "fnstsw ax",
            out("ax") status,
            options(nomem, nostack)
        );
    }
    X87Status::from_bits(status)
}

fn clear_x87_exception() {
    // SAFETY: Clearing x87 FPU exception flags
    unsafe {
        core::arch::asm!("fnclex", options(nomem, nostack));
    }
}

fn read_mxcsr() -> u32 {
    let mut mxcsr: u32 = 0;
    // SAFETY: Reading MXCSR register
    unsafe {
        core::arch::asm!(
            "stmxcsr [{}]",
            in(reg) &mut mxcsr as *mut u32,
            options(nostack)
        );
    }
    mxcsr
}

fn clear_simd_exception() {
    // SAFETY: Clearing SIMD exception flags in MXCSR
    let mut mxcsr = read_mxcsr();
    mxcsr &= !0x3F;
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{}]",
            in(reg) &mxcsr as *const u32,
            options(nostack)
        );
    }
}

fn log_x87_exception(ctx: &ExceptionContext, status: &X87Status) {
    crate::log::logger::log_warning!(
        "x87 FP Exception at {:#x}: IE={} DE={} ZE={} OE={} UE={} PE={} SF={}",
        ctx.instruction_pointer,
        status.invalid_operation(),
        status.denormalized_operand(),
        status.divide_by_zero(),
        status.overflow(),
        status.underflow(),
        status.precision(),
        status.stack_fault()
    );
}

fn log_simd_exception(ctx: &ExceptionContext, mxcsr: u32) {
    crate::log::logger::log_warning!(
        "SIMD FP Exception at {:#x}: MXCSR={:#x}",
        ctx.instruction_pointer,
        mxcsr
    );
}
