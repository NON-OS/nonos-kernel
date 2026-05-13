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

use crate::arch::trap::contract::cause::TrapCause;

pub(super) fn for_cause(cause: &TrapCause) -> &'static str {
    match cause {
        TrapCause::PageFault(_) => "Page Fault",
        TrapCause::ProtectionFault { .. } => "Access Fault",
        TrapCause::StackSegment { .. } => "Stack Fault",
        TrapCause::SegmentNotPresent { .. } => "Segment Fault",
        TrapCause::InvalidTss { .. } => "TSS Fault",
        TrapCause::InvalidOpcode => "Illegal Instruction",
        TrapCause::Alignment => "Alignment Fault",
        TrapCause::DivideError => "Arithmetic",
        TrapCause::Overflow => "Overflow",
        TrapCause::BoundRange => "Bound Range",
        TrapCause::DeviceNotAvailable => "FP/SIMD Trap",
        TrapCause::X87FloatingPoint => "FP",
        TrapCause::SimdFloatingPoint => "SIMD",
        TrapCause::Virtualization => "Virtualization",
        TrapCause::ControlProtection { .. } => "Control Protection",
        TrapCause::DoubleFault { .. } => "Double Fault",
        TrapCause::MachineCheck => "SError",
        TrapCause::Nmi => "NMI",
        TrapCause::OtherException(_) => "Unhandled Synchronous",
    }
}
