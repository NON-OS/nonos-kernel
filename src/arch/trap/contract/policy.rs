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

// LIMIT: until per-process signal injection and graceful task
// termination land, every user-mode synchronous fault dead-ends in the
// fatal sink. The class distinction (UserFault vs Fatal) is preserved
// structurally so signal delivery can be added at this exact site
// without reshaping the contract: Page → SIGSEGV / SIGBUS, Protection
// → SIGSEGV, InvalidOpcode → SIGILL, Alignment → SIGBUS, Arithmetic →
// SIGFPE, Other → SIGSEGV by default. The per-fault routing becomes a
// match on `_kind` once that path exists.
pub(super) fn deliver_user_fault<F: TrapFrame>(
    frame: &F,
    _kind: FaultKind,
    cause: &TrapCause,
) -> ! {
    fatal::enter(frame, cause)
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
