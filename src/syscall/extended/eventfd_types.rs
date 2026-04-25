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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::errno;
use crate::syscall::SyscallResult;

pub const EFD_CLOEXEC: i32 = 0x80000;
pub const EFD_NONBLOCK: i32 = 0x800;
pub const EFD_SEMAPHORE: i32 = 0x1;
pub const EINVAL: i32 = 22;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EBADF: i32 = 9;
pub const EVENTFD_MAX: u64 = u64::MAX - 1;
pub const MAX_EVENTFD_INSTANCES: usize = 1024;

pub struct EventFdInstance {
    counter: AtomicU64,
    pub flags: i32,
}

impl EventFdInstance {
    pub fn new(_id: u32, initval: u32, flags: i32) -> Self {
        Self { counter: AtomicU64::new(initval as u64), flags }
    }
    pub fn is_semaphore(&self) -> bool {
        (self.flags & EFD_SEMAPHORE) != 0
    }
    pub fn is_nonblock(&self) -> bool {
        (self.flags & EFD_NONBLOCK) != 0
    }
    pub fn get_counter(&self) -> u64 {
        self.counter.load(Ordering::Acquire)
    }
    pub fn read(&self) -> Result<u64, i32> {
        loop {
            let current = self.counter.load(Ordering::Acquire);
            if current == 0 {
                if self.is_nonblock() {
                    return Err(EAGAIN);
                }
                core::hint::spin_loop();
                continue;
            }
            if self.is_semaphore() {
                if self
                    .counter
                    .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(1);
                }
            } else {
                if self
                    .counter
                    .compare_exchange(current, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(current);
                }
            }
        }
    }
    pub fn write(&self, value: u64) -> Result<(), i32> {
        if value == u64::MAX {
            return Err(EINVAL);
        }
        loop {
            let current = self.counter.load(Ordering::Acquire);
            if current > EVENTFD_MAX - value {
                if self.is_nonblock() {
                    return Err(EAGAIN);
                }
                core::hint::spin_loop();
                continue;
            }
            if self
                .counter
                .compare_exchange(current, current + value, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

pub static EVENTFD_INSTANCES: Mutex<BTreeMap<u32, EventFdInstance>> = Mutex::new(BTreeMap::new());
pub static NEXT_EVENTFD_ID: AtomicU32 = AtomicU32::new(1);
pub static FD_TO_EVENTFD: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
pub static NEXT_FD: AtomicU32 = AtomicU32::new(5000);

pub fn handle_eventfd2(initval: u32, flags: i32) -> SyscallResult {
    let valid_flags = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
    if (flags & !valid_flags) != 0 {
        return errno(EINVAL);
    }
    if EVENTFD_INSTANCES.lock().len() >= MAX_EVENTFD_INSTANCES {
        return errno(ENOMEM);
    }
    let efd_id = NEXT_EVENTFD_ID.fetch_add(1, Ordering::SeqCst);
    let instance = EventFdInstance::new(efd_id, initval, flags);
    EVENTFD_INSTANCES.lock().insert(efd_id, instance);
    let fd = NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32;
    FD_TO_EVENTFD.lock().insert(fd, efd_id);
    SyscallResult { value: fd as i64, capability_consumed: false, audit_required: false }
}
