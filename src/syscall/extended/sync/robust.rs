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

use super::constants::*;
use super::helpers::wake_futex;
use super::types::{ok, RobustListHead, ROBUST_LISTS, PI_OWNERS};
use crate::syscall::SyscallResult;
use super::super::errno;

pub fn handle_set_robust_list(head: u64, len: u64) -> SyscallResult {
    if len != 24 {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);

    let robust_head = if head == 0 {
        let mut lists = ROBUST_LISTS.lock();
        lists.remove(&pid);
        return ok(0);
    } else {
        // SAFETY: Reading user-provided robust list header
        unsafe {
            RobustListHead {
                list_head: core::ptr::read(head as *const u64),
                len,
                futex_offset: core::ptr::read((head + 8) as *const i64),
                list_op_pending: core::ptr::read((head + 16) as *const u64),
            }
        }
    };

    let mut lists = ROBUST_LISTS.lock();
    lists.insert(pid, robust_head);

    ok(0)
}

pub fn handle_get_robust_list(pid: i32, head_ptr: u64, len_ptr: u64) -> SyscallResult {
    if head_ptr == 0 || len_ptr == 0 {
        return errno(14);
    }

    let target_pid = if pid == 0 {
        crate::process::current_pid().unwrap_or(0)
    } else {
        pid as u32
    };

    let lists = ROBUST_LISTS.lock();
    if let Some(robust_head) = lists.get(&target_pid) {
        // SAFETY: Writing to user-provided pointers
        unsafe {
            core::ptr::write(head_ptr as *mut u64, robust_head.list_head);
            core::ptr::write(len_ptr as *mut u64, robust_head.len);
        }
    } else {
        // SAFETY: Writing to user-provided pointers
        unsafe {
            core::ptr::write(head_ptr as *mut u64, 0);
            core::ptr::write(len_ptr as *mut u64, 0);
        }
    }

    ok(0)
}

pub fn cleanup_robust_list(pid: u32) {
    let robust_head = {
        let mut lists = ROBUST_LISTS.lock();
        lists.remove(&pid)
    };

    if let Some(head) = robust_head {
        let mut entry = head.list_head;
        let mut count = 0;
        const MAX_ENTRIES: usize = 512;

        while entry != 0 && entry != head.list_head && count < MAX_ENTRIES {
            count += 1;

            let futex_addr = if head.futex_offset >= 0 {
                entry.wrapping_add(head.futex_offset as u64)
            } else {
                entry.wrapping_sub((-head.futex_offset) as u64)
            };

            if futex_addr != 0 && (futex_addr & 3) == 0 {
                // SAFETY: Accessing futex memory during cleanup
                unsafe {
                    let current = core::ptr::read_volatile(futex_addr as *const u32);
                    let owner_tid = current & FUTEX_TID_MASK;
                    if owner_tid == pid {
                        let new_val = (current & !FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
                        core::ptr::write_volatile(futex_addr as *mut u32, new_val);
                        wake_futex(futex_addr, 1, FUTEX_BITSET_MATCH_ANY);
                    }
                }
            }

            // SAFETY: Reading next entry pointer
            entry = unsafe { core::ptr::read(entry as *const u64) };
        }

        if head.list_op_pending != 0 {
            let futex_addr = if head.futex_offset >= 0 {
                head.list_op_pending.wrapping_add(head.futex_offset as u64)
            } else {
                head.list_op_pending.wrapping_sub((-head.futex_offset) as u64)
            };

            if futex_addr != 0 && (futex_addr & 3) == 0 {
                // SAFETY: Accessing pending futex during cleanup
                unsafe {
                    let current = core::ptr::read_volatile(futex_addr as *const u32);
                    let owner_tid = current & FUTEX_TID_MASK;
                    if owner_tid == pid {
                        let new_val = (current & !FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
                        core::ptr::write_volatile(futex_addr as *mut u32, new_val);
                        wake_futex(futex_addr, 1, FUTEX_BITSET_MATCH_ANY);
                    }
                }
            }
        }
    }

    let mut pi_owners = PI_OWNERS.lock();
    pi_owners.retain(|_, owner| *owner != pid);
}
