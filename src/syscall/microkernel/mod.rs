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

pub mod capability;
pub mod device;
pub mod ipc;
pub mod memory;
pub mod process;

pub use capability::{sys_cap_check, sys_cap_grant, sys_cap_revoke};
pub use device::{sys_device_claim, sys_device_list, sys_device_release};
pub use ipc::{sys_ipc_call, sys_ipc_recv, sys_ipc_send};
pub use memory::{sys_mmap, sys_munmap};
pub use process::{sys_exit, sys_spawn, sys_yield};

pub const SYS_IPC_SEND: u64 = 0x1000;
pub const SYS_IPC_RECV: u64 = 0x1001;
pub const SYS_IPC_CALL: u64 = 0x1002;
pub const SYS_MMAP: u64 = 0x1010;
pub const SYS_MUNMAP: u64 = 0x1011;
pub const SYS_SPAWN: u64 = 0x1020;
pub const SYS_EXIT: u64 = 0x1021;
pub const SYS_YIELD: u64 = 0x1022;
pub const SYS_CAP_GRANT: u64 = 0x1030;
pub const SYS_CAP_REVOKE: u64 = 0x1031;
pub const SYS_CAP_CHECK: u64 = 0x1032;
pub const SYS_DEVICE_LIST: u64 = 0x1040;
pub const SYS_DEVICE_CLAIM: u64 = 0x1041;
pub const SYS_DEVICE_RELEASE: u64 = 0x1042;

pub fn dispatch_microkernel_syscall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    match nr {
        SYS_IPC_SEND => sys_ipc_send(a0, a1 as *const u8, a2 as usize),
        SYS_IPC_RECV => sys_ipc_recv(a0, a1 as *mut u8, a2 as usize, a3),
        SYS_IPC_CALL => sys_ipc_call(a0, a1 as *const u8, a2 as usize, a3 as *mut u8, a4 as usize),
        SYS_MMAP => sys_mmap(a0, a1 as usize, a2 as u32, a3 as u32),
        SYS_MUNMAP => sys_munmap(a0, a1 as usize),
        SYS_SPAWN => sys_spawn(a0 as *const u8, a1 as usize),
        SYS_EXIT => sys_exit(a0 as i32),
        SYS_YIELD => sys_yield(),
        SYS_CAP_GRANT => sys_cap_grant(a0 as u32, a1),
        SYS_CAP_REVOKE => sys_cap_revoke(a0 as u32, a1),
        SYS_CAP_CHECK => sys_cap_check(a0 as u32, a1),
        SYS_DEVICE_LIST => sys_device_list(a0 as u32, a1, a2),
        SYS_DEVICE_CLAIM => sys_device_claim(a0),
        SYS_DEVICE_RELEASE => sys_device_release(a0),
        _ => -1,
    }
}
