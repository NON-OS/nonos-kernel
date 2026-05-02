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
use super::class::FaultKind;
use super::fatal;
use super::frame::TrapFrame;
use super::signal;

pub(super) fn deliver_user_fault<F: TrapFrame>(
    _frame: &F,
    kind: FaultKind,
    _cause: &TrapCause,
) -> ! {
    let signo = signal::fault_to_signal(kind);
    crate::process::terminate_current_with_signal(signo)
}

// LIMIT: kernel-mode synchronous faults are fatal until extable-style
// fixup descriptors are registered for the user-copy paths. When that
// arrives, a Page fault whose RIP matches a registered fixup site
// resumes at the fixup IP with a documented error code; everything
// else stays fatal because a kernel fault outside a registered fixup
// is by definition a kernel bug.
pub(super) fn deliver_kernel_fault<F: TrapFrame>(
    frame: &F,
    _kind: FaultKind,
    cause: &TrapCause,
) -> ! {
    fatal::enter(frame, cause)
}
