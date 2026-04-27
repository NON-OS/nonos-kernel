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

use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use alloc::collections::BTreeSet;
use spin::Mutex;

const PAGE_SIZE: u64 = 4096;
const MCL_CURRENT: i32 = 1;
const MCL_FUTURE: i32 = 2;
const MCL_ONFAULT: i32 = 4;
const MLOCK_ONFAULT: i32 = 1;

static LOCKED_PAGES: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
static MLOCK_ALL_FLAGS: Mutex<i32> = Mutex::new(0);

/* DEV NOTES eK@nonos.systems
   Memory locking implementation. Marks pages as non-swappable by adding them to
   the locked pages set. The kernel memory manager checks this set before swapping.
*/
pub fn handle_mlock(addr: u64, len: u64) -> SyscallResult {
    if addr & (PAGE_SIZE - 1) != 0 {
        return errno(22);
    }

    if len == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let end = addr.saturating_add(len);
    let pages = ((end - addr) + PAGE_SIZE - 1) / PAGE_SIZE;

    if pages > 1024 * 1024 {
        return errno(12);
    }

    let mut locked = LOCKED_PAGES.lock();
    let mut page_addr = addr;
    while page_addr < end {
        locked.insert(page_addr);
        page_addr = page_addr.saturating_add(PAGE_SIZE);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_mlock2(addr: u64, len: u64, flags: i32) -> SyscallResult {
    if flags != 0 && flags != MLOCK_ONFAULT {
        return errno(22);
    }
    handle_mlock(addr, len)
}

/* DEV NOTES eK@nonos.systems
   Unlock previously locked pages. Removes pages from the locked set, allowing
   them to be swapped out by the memory manager.
*/
pub fn handle_munlock(addr: u64, len: u64) -> SyscallResult {
    if addr & (PAGE_SIZE - 1) != 0 {
        return errno(22);
    }

    if len == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let end = addr.saturating_add(len);
    let mut locked = LOCKED_PAGES.lock();
    let mut page_addr = addr;
    while page_addr < end {
        locked.remove(&page_addr);
        page_addr = page_addr.saturating_add(PAGE_SIZE);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

/* DEV NOTES eK@nonos.systems
   Lock all current and/or future mappings. MCL_CURRENT locks existing pages,
   MCL_FUTURE marks that new allocations should be locked automatically.
*/
pub fn handle_mlockall(flags: i32) -> SyscallResult {
    if flags == 0 || (flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) != 0 {
        return errno(22);
    }

    let mut all_flags = MLOCK_ALL_FLAGS.lock();
    *all_flags = flags;

    SyscallResult { value: 0, capability_consumed: true, audit_required: true }
}

pub fn handle_munlockall() -> SyscallResult {
    let mut locked = LOCKED_PAGES.lock();
    locked.clear();

    let mut all_flags = MLOCK_ALL_FLAGS.lock();
    *all_flags = 0;

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn is_page_locked(addr: u64) -> bool {
    let page_addr = addr & !(PAGE_SIZE - 1);
    LOCKED_PAGES.lock().contains(&page_addr)
}

pub fn should_lock_new_pages() -> bool {
    (*MLOCK_ALL_FLAGS.lock() & MCL_FUTURE) != 0
}
