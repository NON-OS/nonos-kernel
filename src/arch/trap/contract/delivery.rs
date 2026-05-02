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

use super::cause::TrapCause;
use super::class::{FaultKind, TrapClass};
use super::fatal;
use super::frame::TrapFrame;
use super::policy;

/// Single entry from a per-arch shim. Classifies and routes.
///
/// Stays `!` until user faults can return through signal delivery or
/// extable fixup. Today every classified path ends in fatal.
pub fn deliver<F: TrapFrame>(frame: &F) -> ! {
    let cause = frame.cause();
    let class = classify(&cause, frame.from_user());
    match class {
        TrapClass::UserFault(kind) => policy::deliver_user_fault(frame, kind, &cause),
        TrapClass::KernelFault(kind) => policy::deliver_kernel_fault(frame, kind, &cause),
        TrapClass::Fatal => fatal::enter(frame, &cause),
    }
}

fn classify(cause: &TrapCause, from_user: bool) -> TrapClass {
    let kind = match cause {
        TrapCause::DoubleFault { .. } | TrapCause::MachineCheck | TrapCause::Nmi => {
            return TrapClass::Fatal;
        }
        TrapCause::PageFault(_) => FaultKind::Page,
        TrapCause::ProtectionFault { .. }
        | TrapCause::StackSegment { .. }
        | TrapCause::SegmentNotPresent { .. }
        | TrapCause::InvalidTss { .. }
        | TrapCause::ControlProtection { .. } => FaultKind::Protection,
        TrapCause::InvalidOpcode => FaultKind::InvalidOpcode,
        TrapCause::Alignment => FaultKind::Alignment,
        TrapCause::DivideError
        | TrapCause::Overflow
        | TrapCause::BoundRange
        | TrapCause::X87FloatingPoint
        | TrapCause::SimdFloatingPoint => FaultKind::Arithmetic,
        TrapCause::DeviceNotAvailable
        | TrapCause::Virtualization
        | TrapCause::OtherException(_) => FaultKind::Other,
    };
    if from_user {
        TrapClass::UserFault(kind)
    } else {
        TrapClass::KernelFault(kind)
    }
}
