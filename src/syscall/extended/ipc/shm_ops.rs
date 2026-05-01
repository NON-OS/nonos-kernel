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
use super::shm_types::{ok, SHM_ATTACHMENTS, SHM_SEGMENTS};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

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
    if copy_to_user(attach_addr, &segment.data).is_err() {
        return errno(14);
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
            let mut buf = alloc::vec![0u8; segment.size];
            if copy_from_user(shmaddr, &mut buf).is_ok() {
                segment.data.copy_from_slice(&buf);
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
        let _ = pcb.munmap(crate::memory::addr::VirtAddr::new(shmaddr), 4096);
    }
    ok(0)
}
