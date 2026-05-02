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

use super::utils::read_cr2;
use crate::arch::trap::contract::{
    deliver, FaultAccess, PageFaultInfo, TrapCause, TrapFrame,
};
use crate::arch::x86_64::idt::constants::{
    VEC_ALIGNMENT_CHECK, VEC_BOUND_RANGE, VEC_BREAKPOINT, VEC_CONTROL_PROTECTION, VEC_DEBUG,
    VEC_DEVICE_NOT_AVAILABLE, VEC_DIVIDE_ERROR, VEC_DOUBLE_FAULT, VEC_GENERAL_PROTECTION,
    VEC_INVALID_OPCODE, VEC_INVALID_TSS, VEC_MACHINE_CHECK, VEC_NMI, VEC_OVERFLOW,
    VEC_PAGE_FAULT, VEC_SEGMENT_NOT_PRESENT, VEC_SIMD_FP, VEC_STACK_SEGMENT, VEC_VIRTUALIZATION,
    VEC_X87_FP,
};
use crate::arch::x86_64::idt::entry::InterruptFrame;
use crate::sys::serial::{print_hex, print_str};

impl TrapFrame for InterruptFrame {
    fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    fn stack_pointer(&self) -> u64 {
        self.rsp
    }

    fn from_user(&self) -> bool {
        (self.cs & 0x3) == 3
    }

    fn cause(&self) -> TrapCause {
        project_cause(self)
    }
}

/// Route a synchronous-exception frame through the trap delivery
/// contract. Debug and breakpoint vectors are intercepted here because
/// they are recoverable by way of an arch-specific cleanup (clearing
/// the TF bit on `#DB`, single-line log on `#BP`) that has no portable
/// shape — the contract has no policy work to do for them.
pub(crate) fn dispatch_via_contract(frame: &mut InterruptFrame) {
    match frame.vector as u8 {
        VEC_DEBUG => recover_from_debug(frame),
        VEC_BREAKPOINT => log_breakpoint(frame),
        _ => deliver(frame),
    }
}

fn recover_from_debug(frame: &mut InterruptFrame) {
    print_str("[DEBUG] trap at RIP=");
    print_hex(frame.rip);
    print_str("\n");
    frame.rflags &= !(1u64 << 8);
}

fn log_breakpoint(frame: &InterruptFrame) {
    print_str("[BKPT] at RIP=");
    print_hex(frame.rip);
    print_str("\n");
}

fn project_cause(frame: &InterruptFrame) -> TrapCause {
    match frame.vector as u8 {
        VEC_PAGE_FAULT => TrapCause::PageFault(decode_page_fault(frame)),
        VEC_GENERAL_PROTECTION => TrapCause::ProtectionFault { error_code: frame.error_code },
        VEC_STACK_SEGMENT => TrapCause::StackSegment { error_code: frame.error_code },
        VEC_SEGMENT_NOT_PRESENT => TrapCause::SegmentNotPresent { error_code: frame.error_code },
        VEC_INVALID_TSS => TrapCause::InvalidTss { error_code: frame.error_code },
        VEC_INVALID_OPCODE => TrapCause::InvalidOpcode,
        VEC_ALIGNMENT_CHECK => TrapCause::Alignment,
        VEC_DIVIDE_ERROR => TrapCause::DivideError,
        VEC_OVERFLOW => TrapCause::Overflow,
        VEC_BOUND_RANGE => TrapCause::BoundRange,
        VEC_DEVICE_NOT_AVAILABLE => TrapCause::DeviceNotAvailable,
        VEC_X87_FP => TrapCause::X87FloatingPoint,
        VEC_SIMD_FP => TrapCause::SimdFloatingPoint,
        VEC_VIRTUALIZATION => TrapCause::Virtualization,
        VEC_CONTROL_PROTECTION => TrapCause::ControlProtection { error_code: frame.error_code },
        VEC_DOUBLE_FAULT => TrapCause::DoubleFault { error_code: frame.error_code },
        VEC_MACHINE_CHECK => TrapCause::MachineCheck,
        VEC_NMI => TrapCause::Nmi,
        other => TrapCause::OtherException(other),
    }
}

fn decode_page_fault(frame: &InterruptFrame) -> PageFaultInfo {
    let code = frame.error_code;
    let access = if code & (1 << 4) != 0 {
        FaultAccess::InstructionFetch
    } else if code & (1 << 1) != 0 {
        FaultAccess::Write
    } else {
        FaultAccess::Read
    };
    PageFaultInfo {
        fault_address: read_cr2(),
        access,
        present: code & 1 != 0,
        user: code & (1 << 2) != 0,
    }
}
