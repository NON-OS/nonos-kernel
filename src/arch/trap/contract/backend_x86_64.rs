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

use core::arch::asm;

use super::cause::{FaultAccess, PageFaultInfo, TrapCause};
use super::frame::TrapFrame;
use crate::sys::serial::{print_hex, print_str};

pub(super) fn report_fatal<F: TrapFrame>(frame: &F, cause: &TrapCause) {
    print_str("\n!!! KERNEL FATAL TRAP: ");
    print_str(label_for(cause));
    print_str(" !!!\n  RIP=");
    print_hex(frame.instruction_pointer());
    print_str("  RSP=");
    print_hex(frame.stack_pointer());
    print_str("  origin=");
    print_str(if frame.from_user() { "user" } else { "kernel" });
    print_str("\n");
    report_cause_detail(cause);
}

pub(super) fn halt_forever() -> ! {
    // SAFETY: ek@nonos.systems — at this site classification has already
    // produced a fatal verdict, so resuming is not an option. cli stops
    // any further interrupt arrival on this CPU; the hlt loop covers
    // spurious wake-ups (an NMI can break a single hlt) by re-halting
    // immediately. Both insns are nomem/nostack — we touch neither.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

fn label_for(cause: &TrapCause) -> &'static str {
    match cause {
        TrapCause::PageFault(_) => "Page Fault (#PF)",
        TrapCause::ProtectionFault { .. } => "General Protection (#GP)",
        TrapCause::StackSegment { .. } => "Stack Segment (#SS)",
        TrapCause::SegmentNotPresent { .. } => "Segment Not Present (#NP)",
        TrapCause::InvalidTss { .. } => "Invalid TSS (#TS)",
        TrapCause::InvalidOpcode => "Invalid Opcode (#UD)",
        TrapCause::Alignment => "Alignment Check (#AC)",
        TrapCause::DivideError => "Divide Error (#DE)",
        TrapCause::Overflow => "Overflow (#OF)",
        TrapCause::BoundRange => "Bound Range (#BR)",
        TrapCause::DeviceNotAvailable => "Device Not Available (#NM)",
        TrapCause::X87FloatingPoint => "x87 FP (#MF)",
        TrapCause::SimdFloatingPoint => "SIMD FP (#XM)",
        TrapCause::Virtualization => "Virtualization (#VE)",
        TrapCause::ControlProtection { .. } => "Control Protection (#CP)",
        TrapCause::DoubleFault { .. } => "Double Fault (#DF)",
        TrapCause::MachineCheck => "Machine Check (#MC)",
        TrapCause::Nmi => "Non-Maskable Interrupt",
        TrapCause::OtherException(_) => "Unhandled Exception",
    }
}

fn report_cause_detail(cause: &TrapCause) {
    match cause {
        TrapCause::PageFault(info) => report_page_fault(info),
        TrapCause::ProtectionFault { error_code }
        | TrapCause::StackSegment { error_code }
        | TrapCause::SegmentNotPresent { error_code }
        | TrapCause::InvalidTss { error_code }
        | TrapCause::ControlProtection { error_code }
        | TrapCause::DoubleFault { error_code } => {
            print_str("  err=");
            print_hex(*error_code);
            print_str("\n");
        }
        TrapCause::OtherException(vec) => {
            print_str("  vec=");
            print_hex(*vec as u64);
            print_str("\n");
        }
        _ => {}
    }
}

fn report_page_fault(info: &PageFaultInfo) {
    print_str("  CR2=");
    print_hex(info.fault_address);
    print_str(access_label(info.access));
    print_str(if info.present { " present" } else { " not-present" });
    print_str(if info.user { " user" } else { " supervisor" });
    print_str("\n");
}

fn access_label(access: FaultAccess) -> &'static str {
    match access {
        FaultAccess::Read => " read",
        FaultAccess::Write => " write",
        FaultAccess::InstructionFetch => " ifetch",
    }
}
