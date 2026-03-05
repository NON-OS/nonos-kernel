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

use crate::syscall::SyscallResult;
use super::errno;

pub const EFD_CLOEXEC: i32 = 0x80000;
pub const EFD_NONBLOCK: i32 = 0x800;
pub const EFD_SEMAPHORE: i32 = 0x1;

const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EBADF: i32 = 9;

const EVENTFD_MAX: u64 = u64::MAX - 1;

const MAX_EVENTFD_INSTANCES: usize = 1024;

pub struct EventFdInstance {
    counter: AtomicU64,
    flags: i32,
}

impl EventFdInstance {
    fn new(_id: u32, initval: u32, flags: i32) -> Self {
        Self {
            counter: AtomicU64::new(initval as u64),
            flags,
        }
    }

    fn is_semaphore(&self) -> bool {
        (self.flags & EFD_SEMAPHORE) != 0
    }

    fn is_nonblock(&self) -> bool {
        (self.flags & EFD_NONBLOCK) != 0
    }

    fn read(&self) -> Result<u64, i32> {
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
                if self.counter.compare_exchange(
                    current,
                    current - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ).is_ok() {
                    return Ok(1);
                }
            } else {
                if self.counter.compare_exchange(
                    current,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ).is_ok() {
                    return Ok(current);
                }
            }
        }
    }

    fn write(&self, value: u64) -> Result<(), i32> {
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

            let new_value = current + value;
            if self.counter.compare_exchange(
                current,
                new_value,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return Ok(());
            }
        }
    }

    fn get_counter(&self) -> u64 {
        self.counter.load(Ordering::Acquire)
    }
}

static EVENTFD_INSTANCES: Mutex<BTreeMap<u32, EventFdInstance>> = Mutex::new(BTreeMap::new());
static NEXT_EVENTFD_ID: AtomicU32 = AtomicU32::new(1);

static FD_TO_EVENTFD: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
static NEXT_FD: AtomicU32 = AtomicU32::new(5000);

fn allocate_eventfd_fd() -> i32 {
    NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32
}

pub fn handle_eventfd(initval: u32) -> SyscallResult {
    handle_eventfd2(initval, 0)
}

pub fn handle_eventfd2(initval: u32, flags: i32) -> SyscallResult {
    let valid_flags = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
    if (flags & !valid_flags) != 0 {
        return errno(EINVAL);
    }

    let instances = EVENTFD_INSTANCES.lock();
    if instances.len() >= MAX_EVENTFD_INSTANCES {
        drop(instances);
        return errno(ENOMEM);
    }
    drop(instances);

    let efd_id = NEXT_EVENTFD_ID.fetch_add(1, Ordering::SeqCst);
    let instance = EventFdInstance::new(efd_id, initval, flags);

    EVENTFD_INSTANCES.lock().insert(efd_id, instance);

    let fd = allocate_eventfd_fd();
    FD_TO_EVENTFD.lock().insert(fd, efd_id);

    register_eventfd_fd(fd, efd_id, flags);

    SyscallResult {
        value: fd as i64,
        capability_consumed: false,
        audit_required: false,
    }
}

fn register_eventfd_fd(fd: i32, efd_id: u32, flags: i32) {
    let cloexec = (flags & EFD_CLOEXEC) != 0;
    let nonblock = (flags & EFD_NONBLOCK) != 0;

    if let Some(mut fd_table) = get_process_fd_table() {
        fd_table.register_eventfd(fd, efd_id, cloexec, nonblock);
    }
}

fn get_process_fd_table() -> Option<ProcessFdTable> {
    Some(ProcessFdTable)
}

struct ProcessFdTable;

impl ProcessFdTable {
    fn register_eventfd(&mut self, _fd: i32, _efd_id: u32, _cloexec: bool, _nonblock: bool) {
    }
}

pub fn eventfd_read(fd: i32, buf: *mut u8, count: usize) -> Result<usize, i32> {
    if count < 8 {
        return Err(EINVAL);
    }

    let efd_id = match FD_TO_EVENTFD.lock().get(&fd) {
        Some(&id) => id,
        None => return Err(EBADF),
    };

    let instances = EVENTFD_INSTANCES.lock();
    let instance = match instances.get(&efd_id) {
        Some(inst) => inst,
        None => return Err(EBADF),
    };

    let value = instance.read()?;
    drop(instances);

    unsafe {
        let value_bytes = value.to_le_bytes();
        core::ptr::copy_nonoverlapping(value_bytes.as_ptr(), buf, 8);
    }

    Ok(8)
}

pub fn eventfd_write(fd: i32, buf: *const u8, count: usize) -> Result<usize, i32> {
    if count < 8 {
        return Err(EINVAL);
    }

    let efd_id = match FD_TO_EVENTFD.lock().get(&fd) {
        Some(&id) => id,
        None => return Err(EBADF),
    };

    let value = unsafe {
        let mut bytes = [0u8; 8];
        core::ptr::copy_nonoverlapping(buf, bytes.as_mut_ptr(), 8);
        u64::from_le_bytes(bytes)
    };

    let instances = EVENTFD_INSTANCES.lock();
    let instance = match instances.get(&efd_id) {
        Some(inst) => inst,
        None => return Err(EBADF),
    };

    instance.write(value)?;
    drop(instances);

    Ok(8)
}

pub fn eventfd_close(fd: i32) -> Result<(), i32> {
    let efd_id = match FD_TO_EVENTFD.lock().remove(&fd) {
        Some(id) => id,
        None => return Err(EBADF),
    };

    EVENTFD_INSTANCES.lock().remove(&efd_id);
    Ok(())
}

pub struct EventFdInfo {
    pub counter: u64,
    pub is_semaphore: bool,
    pub is_nonblock: bool,
}

pub fn get_eventfd_info(efd_id: usize) -> Option<EventFdInfo> {
    let instances = EVENTFD_INSTANCES.lock();
    instances.get(&(efd_id as u32)).map(|inst| EventFdInfo {
        counter: inst.get_counter(),
        is_semaphore: inst.is_semaphore(),
        is_nonblock: inst.is_nonblock(),
    })
}

pub fn eventfd_is_readable(efd_id: usize) -> bool {
    let instances = EVENTFD_INSTANCES.lock();
    instances.get(&(efd_id as u32))
        .map(|inst| inst.get_counter() > 0)
        .unwrap_or(false)
}

pub fn eventfd_is_writable(efd_id: usize) -> bool {
    let instances = EVENTFD_INSTANCES.lock();
    instances.get(&(efd_id as u32))
        .map(|inst| inst.get_counter() < EVENTFD_MAX)
        .unwrap_or(false)
}

pub fn fd_to_eventfd_id(fd: i32) -> Option<u32> {
    FD_TO_EVENTFD.lock().get(&fd).copied()
}

pub fn is_eventfd(fd: i32) -> bool {
    FD_TO_EVENTFD.lock().contains_key(&fd)
}

pub fn eventfd_count() -> usize {
    EVENTFD_INSTANCES.lock().len()
}

pub fn get_eventfd_stats() -> EventFdStats {
    let instances = EVENTFD_INSTANCES.lock();
    let mut total_counter = 0u64;
    let mut semaphore_count = 0;
    let mut nonblock_count = 0;

    for inst in instances.values() {
        total_counter = total_counter.saturating_add(inst.get_counter());
        if inst.is_semaphore() {
            semaphore_count += 1;
        }
        if inst.is_nonblock() {
            nonblock_count += 1;
        }
    }

    EventFdStats {
        active_count: instances.len(),
        total_counter_sum: total_counter,
        semaphore_mode_count: semaphore_count,
        nonblock_count,
    }
}

pub struct EventFdStats {
    pub active_count: usize,
    pub total_counter_sum: u64,
    pub semaphore_mode_count: usize,
    pub nonblock_count: usize,
}
