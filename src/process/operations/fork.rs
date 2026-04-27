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

use super::super::clone_flags::CloneArgs;
use super::super::core::{current_process, ProcessControlBlock};
use super::clone::clone_process;
use alloc::sync::Arc;

pub fn clone3(args: &CloneArgs, size: usize) -> Result<u32, i32> {
    if size < core::mem::size_of::<CloneArgs>() {
        return Err(-22);
    }
    clone_process(
        args.flags,
        args.stack + args.stack_size,
        args.parent_tid,
        args.child_tid,
        args.tls,
    )
}

pub fn fork_process(_parent: &Arc<ProcessControlBlock>) -> Result<u32, &'static str> {
    clone_process(0, 0, 0, 0, 0).map_err(|_| "fork failed")
}

pub fn fork() -> Result<u32, &'static str> {
    let parent = current_process().ok_or("no current process")?;
    fork_process(&parent)
}
