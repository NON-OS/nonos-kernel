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

use crate::process::core::Pid;

pub(crate) const SERVICE_STACK_SIZE: usize = 64 * 1024;
const MAX_SERVICE_STACKS: usize = 8;

static mut SERVICE_STACKS: [[u8; SERVICE_STACK_SIZE]; MAX_SERVICE_STACKS] =
    [[0u8; SERVICE_STACK_SIZE]; MAX_SERVICE_STACKS];

pub(crate) fn allocate_service_stack(pid: Pid) -> u64 {
    let idx = (pid as usize).saturating_sub(1) % MAX_SERVICE_STACKS;
    let stack_ptr = unsafe { SERVICE_STACKS[idx].as_mut_ptr() };
    (stack_ptr as u64) + SERVICE_STACK_SIZE as u64 - 16
}
