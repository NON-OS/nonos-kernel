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

mod constants;
mod types;
mod transitions;
mod context;
mod memory;
mod api;

pub use constants::{
    USER_HEAP_START, USER_STACK_BASE, USER_STACK_SIZE,
    USER_CS, USER_DS, KERNEL_CS, KERNEL_DS, USER_RFLAGS,
    KERNEL_STACK_SIZE, USER_CODE_START,
};
pub use types::{
    ThreadState, BlockReason, KernelStack, FpuState, ThreadControlBlock,
    InterruptFrame, UserContext, ExecContext,
};
pub use transitions::{
    enable_smep as transitions_enable_smep, enable_smap as transitions_enable_smap,
    jump_to_usermode, return_to_usermode, sysret_to_usermode, exec_process,
};
pub use context::{
    switch_context, switch_to_new_thread, write_fs_base, read_fs_base,
    write_gs_base, write_kernel_gs_base, enable_smep, enable_smap,
    stac, clac, with_user_access,
};
pub use memory::*;
pub use api::*;
