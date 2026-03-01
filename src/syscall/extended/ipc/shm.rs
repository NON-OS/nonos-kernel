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
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use crate::syscall::SyscallResult;
use super::super::errno;
use super::constants::*;

fn ok(value: i64) -> SyscallResult {
    SyscallResult { value, capability_consumed: false, audit_required: false }
}

#[derive(Clone)]
pub struct ShmSegment {
    pub key: u64,
    pub size: usize,
    pub flags: i32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub atime: u64,
    pub dtime: u64,
    pub ctime: u64,
    pub cpid: u32,
    pub lpid: u32,
    pub nattch: u32,
    pub data: Vec<u8>,
    pub marked_for_removal: bool,
}

pub static SHM_SEGMENTS: Mutex<BTreeMap<i32, ShmSegment>> = Mutex::new(BTreeMap::new());
pub static SHM_NEXT_ID: AtomicI32 = AtomicI32::new(1);
pub static SHM_ATTACHMENTS: Mutex<BTreeMap<(u32, u64), i32>> = Mutex::new(BTreeMap::new());

pub fn handle_shmget(key: u64, size: u64, shmflg: i32) -> SyscallResult {
    let size = size as usize;

    if size < SHMMIN || size > SHMMAX {
        return errno(22);
    }

    let mut segments = SHM_SEGMENTS.lock();

    if key != IPC_PRIVATE {
        for (&id, seg) in segments.iter() {
            if seg.key == key {
                if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                    return errno(17);
                }
                return ok(id as i64);
            }
        }
    }

    if key != IPC_PRIVATE && (shmflg & IPC_CREAT) == 0 {
        return errno(2);
    }

    if segments.len() >= SHMMNI {
        return errno(28);
    }

    let id = SHM_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let pid = crate::process::current_pid().unwrap_or(0);
    let now = crate::time::timestamp_millis();

    let segment = ShmSegment {
        key,
        size,
        flags: shmflg,
        mode: (shmflg & 0o777) as u16,
        uid: 0,
        gid: 0,
        cuid: 0,
        cgid: 0,
        atime: 0,
        dtime: 0,
        ctime: now,
        cpid: pid,
        lpid: 0,
        nattch: 0,
        data: alloc::vec![0u8; size],
        marked_for_removal: false,
    };

    segments.insert(id, segment);
    ok(id as i64)
}

pub fn handle_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> SyscallResult {
    let mut segments = SHM_SEGMENTS.lock();

    let segment = match segments.get_mut(&shmid) {
        Some(s) => s,
        None => return errno(22),
    };

    if segment.marked_for_removal {
        return errno(43);
    }

    let attach_addr = if shmaddr == 0 {
        let pcb = match crate::process::current_process() {
            Some(p) => p,
            None => return errno(14),
        };

        let flags = x86_64::structures::paging::PageTableFlags::WRITABLE;
        match pcb.mmap(None, segment.size, flags) {
            Ok(va) => va.as_u64(),
            Err(_) => return errno(12),
        }
    } else {
        if (shmflg & SHM_RND) != 0 {
            shmaddr & !0xFFF
        } else if (shmaddr & 0xFFF) != 0 {
            return errno(22);
        } else {
            shmaddr
        }
    };

    // SAFETY: attach_addr was allocated by mmap or provided by user.
    unsafe {
        let ptr = attach_addr as *mut u8;
        core::ptr::copy_nonoverlapping(segment.data.as_ptr(), ptr, segment.size);
    }

    let pid = crate::process::current_pid().unwrap_or(0);
    segment.nattch += 1;
    segment.atime = crate::time::timestamp_millis();
    segment.lpid = pid;

    SHM_ATTACHMENTS.lock().insert((pid, attach_addr), shmid);

    ok(attach_addr as i64)
}

pub fn handle_shmdt(shmaddr: u64) -> SyscallResult {
    if shmaddr == 0 || (shmaddr & 0xFFF) != 0 {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);

    let shmid = {
        let mut attachments = SHM_ATTACHMENTS.lock();
        match attachments.remove(&(pid, shmaddr)) {
            Some(id) => id,
            None => return errno(22),
        }
    };

    let mut segments = SHM_SEGMENTS.lock();

    if let Some(segment) = segments.get_mut(&shmid) {
        if segment.nattch > 0 {
            // SAFETY: shmaddr was previously attached.
            unsafe {
                let ptr = shmaddr as *const u8;
                let slice = core::slice::from_raw_parts(ptr, segment.size);
                segment.data.copy_from_slice(slice);
            }
        }

        segment.nattch = segment.nattch.saturating_sub(1);
        segment.dtime = crate::time::timestamp_millis();
        segment.lpid = pid;

        if segment.marked_for_removal && segment.nattch == 0 {
            segments.remove(&shmid);
        }
    }

    if let Some(pcb) = crate::process::current_process() {
        let _ = pcb.munmap(x86_64::VirtAddr::new(shmaddr), 4096);
    }

    ok(0)
}

pub fn handle_shmctl(shmid: i32, cmd: i32, buf: u64) -> SyscallResult {
    let mut segments = SHM_SEGMENTS.lock();

    match cmd {
        IPC_RMID => {
            if let Some(segment) = segments.get_mut(&shmid) {
                if segment.nattch == 0 {
                    segments.remove(&shmid);
                } else {
                    segment.marked_for_removal = true;
                }
                ok(0)
            } else {
                errno(22)
            }
        }
        IPC_STAT | SHM_STAT => {
            if buf == 0 {
                return errno(14);
            }
            if let Some(segment) = segments.get(&shmid) {
                // SAFETY: buf is user-provided pointer for shmid_ds struct.
                unsafe {
                    let ptr = buf as *mut u64;
                    core::ptr::write(ptr.add(0), segment.key);
                    core::ptr::write(ptr.add(1), segment.uid as u64);
                    core::ptr::write(ptr.add(2), segment.gid as u64);
                    core::ptr::write(ptr.add(3), segment.mode as u64);
                    core::ptr::write(ptr.add(4), segment.size as u64);
                    core::ptr::write(ptr.add(5), segment.atime);
                    core::ptr::write(ptr.add(6), segment.dtime);
                    core::ptr::write(ptr.add(7), segment.ctime);
                    core::ptr::write(ptr.add(8), segment.cpid as u64);
                    core::ptr::write(ptr.add(9), segment.lpid as u64);
                    core::ptr::write(ptr.add(10), segment.nattch as u64);
                }
                ok(0)
            } else {
                errno(22)
            }
        }
        IPC_SET => {
            if buf == 0 {
                return errno(14);
            }
            if let Some(segment) = segments.get_mut(&shmid) {
                // SAFETY: buf is user-provided pointer for shmid_ds struct.
                unsafe {
                    let ptr = buf as *const u64;
                    segment.uid = core::ptr::read(ptr.add(1)) as u32;
                    segment.gid = core::ptr::read(ptr.add(2)) as u32;
                    segment.mode = core::ptr::read(ptr.add(3)) as u16;
                }
                segment.ctime = crate::time::timestamp_millis();
                ok(0)
            } else {
                errno(22)
            }
        }
        SHM_INFO => {
            if buf == 0 {
                return errno(14);
            }
            // SAFETY: buf is user-provided pointer for shminfo struct.
            unsafe {
                let ptr = buf as *mut u64;
                core::ptr::write(ptr.add(0), segments.len() as u64);
                core::ptr::write(ptr.add(1), SHMMAX as u64);
                core::ptr::write(ptr.add(2), SHMMNI as u64);
            }
            ok(segments.len() as i64)
        }
        _ => errno(22),
    }
}
