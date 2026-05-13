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

// Scheduler's PCB->user delegator. Per-arch logic lives in
// `arch::<arch>::context::switch`; this file is the call site so the
// scheduler core stays arch-neutral.

pub(crate) fn switch_to_process(pid: u32) {
    crate::arch::context::switch_to_user_pcb(pid);
}
