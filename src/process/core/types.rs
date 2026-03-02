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

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};


pub type Pid = u32;
pub type Tid = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    New,
    Ready,
    Running,
    Sleeping,
    Stopped,
    Zombie(i32),
    Terminated(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Idle,
    Low,
    Normal,
    High,
    RealTime,
    Realtime,  // Alias for RealTime
}

#[derive(Debug, Clone)]
pub struct Vma {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub flags: PageTableFlags,
}

#[derive(Debug)]
pub struct MemoryState {
    pub code_start: VirtAddr,
    pub code_end: VirtAddr,
    pub vmas: Vec<Vma>,
    pub resident_pages: AtomicU64,
    pub(crate) next_va: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct IsolationFlags {
    pub no_network: bool,
    pub no_filesystem: bool,
    pub no_ipc: bool,
    pub no_devices: bool,
    pub memory_isolated: bool,
}

impl Default for IsolationFlags {
    fn default() -> Self {
        Self {
            no_network: true,
            no_filesystem: true,
            no_ipc: true,
            no_devices: true,
            memory_isolated: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SuspendedContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub suspended_at: u64,
    pub previous_state: ProcessState,
}

#[inline]
pub fn align_up(v: u64, a: u64) -> u64 {
    (v + (a - 1)) & !(a - 1)
}

#[inline]
pub fn overlaps(vmas: &[Vma], start: VirtAddr, len: usize) -> bool {
    let s = start.as_u64();
    let e = s + len as u64;
    for v in vmas {
        let vs = v.start.as_u64();
        let ve = v.end.as_u64();
        if !(e <= vs || s >= ve) {
            return true;
        }
    }
    false
}
