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

use core::sync::atomic::Ordering;
use super::super::core::{current_process, allocate_tid, PROCESS_TABLE};
use super::super::clone_flags::*;
use super::super::clone_pcb::{create_thread_pcb, create_process_pcb};
use super::validate::validate_clone_flags;
use crate::usercopy::write_user_value;

pub fn clone_process(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) -> Result<u32, i32> {
    let parent = current_process().ok_or(-1i32)?;
    if !validate_clone_flags(flags) { return Err(-22); }

    let parent_priority = *parent.priority.lock();
    let parent_caps = parent.caps_bits.load(Ordering::Acquire);
    let parent_tgid = parent.tgid.load(Ordering::Acquire);
    let parent_pgid = parent.pgid.load(Ordering::Acquire);
    let parent_sid = parent.sid.load(Ordering::Acquire);
    let child_tid_val = allocate_tid().ok_or(-11i32)?;
    let is_thread = (flags & CLONE_VM) != 0;

    let child_name = if is_thread {
        alloc::format!("{}.thread.{}", parent.name.lock(), child_tid_val)
    } else {
        alloc::format!("{}.fork", parent.name.lock())
    };

    let child_pcb = if is_thread {
        create_thread_pcb(&parent, child_tid_val, &child_name, parent_priority, parent_caps, parent_tgid, parent_pgid, parent_sid, flags, stack, tls, child_tid)?
    } else {
        create_process_pcb(&parent, child_tid_val, &child_name, parent_priority, parent_caps, parent_pgid, parent_sid, flags)?
    };

    handle_tid_settings(flags, parent_tid, child_tid, child_tid_val, &child_pcb)?;
    PROCESS_TABLE.add(child_pcb.clone());
    if is_thread {
        if let Some(ref tg) = parent.thread_group { tg.add_thread(child_tid_val); }
    }
    crate::sched::add_to_run_queue(child_tid_val);
    Ok(child_tid_val)
}

fn handle_tid_settings(flags: u64, parent_tid: u64, child_tid: u64, child_tid_val: u32, child_pcb: &alloc::sync::Arc<super::super::core::ProcessControlBlock>) -> Result<(), i32> {
    if (flags & CLONE_PARENT_SETTID) != 0 && parent_tid != 0 {
        if write_user_value::<u32>(parent_tid, &child_tid_val).is_err() { return Err(-14); }
    }
    if (flags & CLONE_CHILD_SETTID) != 0 && child_tid != 0 {
        child_pcb.set_child_tid.store(child_tid, Ordering::Release);
        let _ = write_user_value::<u32>(child_tid, &child_tid_val);
    }
    if (flags & CLONE_CHILD_CLEARTID) != 0 && child_tid != 0 {
        child_pcb.clear_child_tid.store(child_tid, Ordering::Release);
    }
    Ok(())
}
