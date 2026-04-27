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

use super::state::{clear_traced, is_traced, set_seized, set_traced};

pub fn do_traceme() -> Result<(), i32> {
    let pid = crate::process::current_pid().ok_or(3)?;
    let ppid = crate::process::get_parent_pid(pid).ok_or(3)?;
    if is_traced(pid) {
        return Err(1);
    }
    set_traced(pid, ppid);
    Ok(())
}

pub fn do_attach(pid: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if pid == tracer {
        return Err(1);
    }
    if is_traced(pid) {
        return Err(1);
    }
    if !can_attach(tracer, pid) {
        return Err(1);
    }
    set_traced(pid, tracer);
    let _ = crate::process::stop_process(pid);
    let _ = crate::syscall::signals::send_signal_to_process(pid, 19);
    Ok(())
}

pub fn do_seize(pid: u32, _options: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if pid == tracer {
        return Err(1);
    }
    if is_traced(pid) {
        return Err(1);
    }
    if !can_attach(tracer, pid) {
        return Err(1);
    }
    set_seized(pid, tracer);
    Ok(())
}

pub fn do_detach(pid: u32, _signal: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if !verify_tracer(pid, tracer) {
        return Err(3);
    }
    clear_traced(pid);
    let _ = crate::process::resume_process(pid);
    Ok(())
}

fn can_attach(tracer: u32, target: u32) -> bool {
    let tracer_uid = crate::process::get_uid(tracer).unwrap_or(u32::MAX);
    let target_uid = crate::process::get_uid(target).unwrap_or(u32::MAX);
    tracer_uid == 0 || tracer_uid == target_uid
}

fn verify_tracer(pid: u32, tracer: u32) -> bool {
    super::state::get_tracer(pid) == Some(tracer)
}

pub fn do_interrupt(pid: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if !verify_tracer(pid, tracer) {
        return Err(3);
    }
    let _ = crate::process::stop_process(pid);
    Ok(())
}

pub fn do_listen(pid: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if !verify_tracer(pid, tracer) {
        return Err(3);
    }
    Ok(())
}
