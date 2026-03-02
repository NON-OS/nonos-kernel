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

pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_FS: u64 = 0x00000200;
pub const CLONE_FILES: u64 = 0x00000400;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_THREAD: u64 = 0x00010000;
pub const CLONE_DETACHED: u64 = 0x00400000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_PARENT: u64 = 0x00008000;
pub const CLONE_STOPPED: u64 = 0x02000000;
pub const CLONE_VFORK: u64 = 0x00004000;
pub const CLONE_SIGHAND_MASK: u64 = 0x000000FF;

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}
