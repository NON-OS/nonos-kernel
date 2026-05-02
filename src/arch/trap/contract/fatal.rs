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

use super::backend;
use super::cause::TrapCause;
use super::frame::TrapFrame;

/// Fatal sink. Called when classification has determined the trap is
/// non-recoverable (architecturally fatal cause, or any synchronous
/// fault that today's policy buckets cannot recover). Reports the trap
/// through the per-arch backend's diagnostic sink and parks the CPU.
pub(super) fn enter<F: TrapFrame>(frame: &F, cause: &TrapCause) -> ! {
    backend::report_fatal(frame, cause);
    backend::halt_forever()
}
