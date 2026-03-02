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

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::core::{current_process, allocate_tid, ProcessControlBlock, PROCESS_TABLE};
use super::clone_flags::*;
use super::clone_pcb::{create_thread_pcb, create_process_pcb};

pub fn clone_process(
    flags: u64,
    stack: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
) -> Result<u32, i32> {
    let parent = current_process().ok_or(-1i32)?;

    if !validate_clone_flags(flags) {
        return Err(-22);
    }

    let parent_priority = *parent.priority.lock();
    let parent_caps = parent.caps_bits.load(Ordering::Acquire);
    let parent_tgid = parent.tgid.load(Ordering::Acquire);
    let parent_pgid = parent.pgid.load(Ordering::Relaxed);
    let parent_sid = parent.sid.load(Ordering::Relaxed);

    let child_tid_val = allocate_tid();
    let is_thread = (flags & CLONE_VM) != 0;

    let child_name = if is_thread {
        let name = parent.name.lock();
        alloc::format!("{}.thread.{}", name, child_tid_val)
    } else {
        let name = parent.name.lock();
        alloc::format!("{}.fork", name)
    };

    let child_pcb = if is_thread {
        create_thread_pcb(
            &parent, child_tid_val, &child_name, parent_priority, parent_caps,
            parent_tgid, parent_pgid, parent_sid, flags, stack, tls, child_tid,
        )?
    } else {
        create_process_pcb(
            &parent, child_tid_val, &child_name, parent_priority, parent_caps,
            parent_pgid, parent_sid, flags,
        )?
    };

    if (flags & CLONE_PARENT_SETTID) != 0 && parent_tid != 0 {
        // SAFETY: Parent provided pointer, responsible for validity.
        unsafe {
            let ptr = parent_tid as *mut u32;
            if ptr.is_aligned() {
                core::ptr::write_volatile(ptr, child_tid_val);
            }
        }
    }

    if (flags & CLONE_CHILD_SETTID) != 0 && child_tid != 0 {
        child_pcb.set_child_tid.store(child_tid, Ordering::Release);
        // SAFETY: Child TID pointer in shared memory space.
        unsafe {
            let ptr = child_tid as *mut u32;
            if ptr.is_aligned() {
                core::ptr::write_volatile(ptr, child_tid_val);
            }
        }
    }

    if (flags & CLONE_CHILD_CLEARTID) != 0 && child_tid != 0 {
        child_pcb.clear_child_tid.store(child_tid, Ordering::Release);
    }

    PROCESS_TABLE.add(child_pcb);

    if is_thread {
        if let Some(ref tg) = parent.thread_group {
            tg.add_thread(child_tid_val);
        }
    }

    Ok(child_tid_val)
}

fn validate_clone_flags(flags: u64) -> bool {
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 {
        return false;
    }
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 {
        return false;
    }
    if (flags & CLONE_FS) != 0 && (flags & CLONE_NEWNS) != 0 {
        return false;
    }
    true
}

pub fn clone3(args: &CloneArgs, size: usize) -> Result<u32, i32> {
    if size < core::mem::size_of::<CloneArgs>() {
        return Err(-22);
    }
    clone_process(args.flags, args.stack + args.stack_size, args.parent_tid, args.child_tid, args.tls)
}

pub fn fork_process(_parent: &Arc<ProcessControlBlock>) -> Result<u32, &'static str> {
    clone_process(0, 0, 0, 0, 0).map_err(|_| "fork failed")
}

pub fn fork() -> Result<u32, &'static str> {
    let parent = current_process().ok_or("no current process")?;
    fork_process(&parent)
}
