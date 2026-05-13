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

use crate::arch::riscv64::interrupts::cause::{ExceptionCode, TrapCause as RiscvCause};
use crate::arch::riscv64::interrupts::frame::TrapFrame;
use crate::arch::trap::contract::{FaultAccess, PageFaultInfo, TrapCause};

// scause MSB selects interrupt vs exception. Interrupts arriving via
// the contract are asynchronous and fatal by construction (the routine
// dispatch is in interrupts::handlers, not here). Ecall is intentionally
// classified as OtherException — the asm dispatcher routes ECALL into
// the syscall path before invoking `contract::deliver`.
pub(super) fn project(frame: &TrapFrame) -> TrapCause {
    match RiscvCause::from_scause(frame.scause) {
        RiscvCause::Interrupt(_) => TrapCause::Nmi,
        RiscvCause::Exception(code) => exception(code, frame),
    }
}

fn exception(code: ExceptionCode, frame: &TrapFrame) -> TrapCause {
    match code {
        ExceptionCode::LoadPageFault => TrapCause::PageFault(page_fault(frame, FaultAccess::Read)),
        ExceptionCode::StorePageFault => TrapCause::PageFault(page_fault(frame, FaultAccess::Write)),
        ExceptionCode::InstructionPageFault => {
            TrapCause::PageFault(page_fault(frame, FaultAccess::InstructionFetch))
        }
        ExceptionCode::LoadAccessFault
        | ExceptionCode::StoreAccessFault
        | ExceptionCode::InstructionAccessFault => {
            TrapCause::ProtectionFault { error_code: frame.stval as u64 }
        }
        ExceptionCode::IllegalInstruction => TrapCause::InvalidOpcode,
        ExceptionCode::InstructionMisaligned
        | ExceptionCode::LoadMisaligned
        | ExceptionCode::StoreMisaligned => TrapCause::Alignment,
        ExceptionCode::Breakpoint => TrapCause::OtherException(3),
        ExceptionCode::UserEcall => TrapCause::OtherException(8),
        ExceptionCode::SupervisorEcall => TrapCause::OtherException(9),
        ExceptionCode::MachineEcall => TrapCause::OtherException(11),
        ExceptionCode::Unknown(c) => TrapCause::OtherException(c as u8),
    }
}

// `present` is not exposed by RISC-V; the page-table walk hardware
// either delivered page-fault (entry missing or invalid) or
// access-fault (permission). Page-fault always implies not-present
// from the PTE.V bit perspective.
fn page_fault(frame: &TrapFrame, access: FaultAccess) -> PageFaultInfo {
    PageFaultInfo {
        fault_address: frame.stval as u64,
        access,
        present: false,
        user: frame.is_from_user(),
    }
}
