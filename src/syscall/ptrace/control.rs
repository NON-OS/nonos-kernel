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

use super::state::{clear_traced, get_tracer, set_options, set_singlestep, set_syscall_entry};

pub fn do_cont(pid: u32, signal: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    set_singlestep(pid, false);
    let _ = crate::process::resume_process(pid);
    if signal != 0 {
        let _ = crate::syscall::signals::send_signal_to_process(pid, signal);
    }
    Ok(())
}

pub fn do_singlestep(pid: u32, signal: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    set_singlestep(pid, true);
    enable_trap_flag(pid)?;
    let _ = crate::process::resume_process(pid);
    if signal != 0 {
        let _ = crate::syscall::signals::send_signal_to_process(pid, signal);
    }
    Ok(())
}

pub fn do_syscall(pid: u32, signal: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    set_syscall_entry(pid, true);
    let _ = crate::process::resume_process(pid);
    if signal != 0 {
        let _ = crate::syscall::signals::send_signal_to_process(pid, signal);
    }
    Ok(())
}

pub fn do_kill(pid: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    clear_traced(pid);
    let _ = crate::syscall::signals::send_signal_to_process(pid, 9);
    Ok(())
}

pub fn do_setoptions(pid: u32, options: u32) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    set_options(pid, options)
}

pub fn do_geteventmsg(pid: u32, data: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if data == 0 {
        return Err(14);
    }
    let msg = super::state::get_event_msg(pid);
    crate::usercopy::write_user_value(data, &msg).map_err(|_| 14)
}

fn enable_trap_flag(pid: u32) -> Result<(), i32> {
    if super::saved_context::modify_saved_context(pid as u64, |ctx| {
        ctx.rflags |= 0x100;
    }) {
        Ok(())
    } else {
        Err(3)
    }
}

pub fn disable_trap_flag(pid: u32) -> Result<(), i32> {
    if super::saved_context::modify_saved_context(pid as u64, |ctx| {
        ctx.rflags &= !0x100;
    }) {
        Ok(())
    } else {
        Err(3)
    }
}
