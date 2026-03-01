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

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use spin::Mutex;

use crate::syscall::SyscallResult;

#[derive(Clone, Debug)]
pub(super) struct FutexWaiter {
    pub(super) pid: u32,
    pub(super) bitset: u32,
    pub(super) is_pi: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RobustListHead {
    pub list_head: u64,
    pub len: u64,
    pub futex_offset: i64,
    pub list_op_pending: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FutexStats {
    pub total_waits: u64,
    pub total_wakes: u64,
    pub total_timeouts: u64,
    pub active_waiters: usize,
    pub active_pi_locks: usize,
    pub robust_lists_registered: usize,
}

pub(super) static FUTEX_WAITER_MAP: Mutex<BTreeMap<u64, Vec<FutexWaiter>>> = Mutex::new(BTreeMap::new());
pub(super) static ROBUST_LISTS: Mutex<BTreeMap<u32, RobustListHead>> = Mutex::new(BTreeMap::new());
pub(super) static PI_OWNERS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

pub(super) static FUTEX_WAITS: AtomicU64 = AtomicU64::new(0);
pub(super) static FUTEX_WAKES: AtomicU64 = AtomicU64::new(0);
pub(super) static FUTEX_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

pub(super) fn ok(value: i64) -> SyscallResult {
    SyscallResult { value, capability_consumed: false, audit_required: false }
}
