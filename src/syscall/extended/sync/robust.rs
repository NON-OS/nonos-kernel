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

use super::super::errno;
use super::constants::*;
use super::helpers::wake_futex;
use super::types::{ok, RobustListHead, PI_OWNERS, ROBUST_LISTS};
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

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
        let list_head: u64 = match read_user_value(head) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let head_off8 = match head.checked_add(8) {
            Some(v) => v,
            None => return errno(14),
        };
        let futex_offset: i64 = match read_user_value(head_off8) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let head_off16 = match head.checked_add(16) {
            Some(v) => v,
            None => return errno(14),
        };
        let list_op_pending: u64 = match read_user_value(head_off16) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        RobustListHead { list_head, len, futex_offset, list_op_pending }
    };

    let mut lists = ROBUST_LISTS.lock();
    lists.insert(pid, robust_head);

    ok(0)
}

pub fn handle_get_robust_list(pid: i32, head_ptr: u64, len_ptr: u64) -> SyscallResult {
    if head_ptr == 0 || len_ptr == 0 {
        return errno(14);
    }

    let target_pid = if pid == 0 { crate::process::current_pid().unwrap_or(0) } else { pid as u32 };

    let lists = ROBUST_LISTS.lock();
    if let Some(robust_head) = lists.get(&target_pid) {
        if write_user_value(head_ptr, &robust_head.list_head).is_err() {
            return errno(14);
        }
        if write_user_value(len_ptr, &robust_head.len).is_err() {
            return errno(14);
        }
    } else {
        let zero: u64 = 0;
        if write_user_value(head_ptr, &zero).is_err() {
            return errno(14);
        }
        if write_user_value(len_ptr, &zero).is_err() {
            return errno(14);
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
        process_robust_entries(pid, &head);
    }

    let mut pi_owners = PI_OWNERS.lock();
    pi_owners.retain(|_, owner| *owner != pid);
}

fn process_robust_entries(pid: u32, head: &RobustListHead) {
    let mut entry = head.list_head;
    let mut count = 0;
    const MAX_ENTRIES: usize = 512;

    while entry != 0 && entry != head.list_head && count < MAX_ENTRIES {
        count += 1;
        let futex_addr = compute_futex_addr(entry, head.futex_offset);
        if futex_addr != 0 && (futex_addr & 3) == 0 {
            mark_futex_owner_died(futex_addr, pid);
        }
        entry = read_user_value(entry).unwrap_or(0);
    }

    if head.list_op_pending != 0 {
        let futex_addr = compute_futex_addr(head.list_op_pending, head.futex_offset);
        if futex_addr != 0 && (futex_addr & 3) == 0 {
            mark_futex_owner_died(futex_addr, pid);
        }
    }
}

fn compute_futex_addr(entry: u64, offset: i64) -> u64 {
    if offset >= 0 {
        entry.checked_add(offset as u64).unwrap_or(0)
    } else {
        entry.checked_sub((-offset) as u64).unwrap_or(0)
    }
}

fn mark_futex_owner_died(futex_addr: u64, pid: u32) {
    let current: u32 = match read_user_value(futex_addr) {
        Ok(v) => v,
        Err(_) => return,
    };
    let owner_tid = current & FUTEX_TID_MASK;
    if owner_tid == pid {
        let new_val = (current & !FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
        let _ = write_user_value(futex_addr, &new_val);
        wake_futex(futex_addr, 1, FUTEX_BITSET_MATCH_ANY);
    }
}
