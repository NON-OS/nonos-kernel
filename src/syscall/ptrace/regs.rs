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

use super::state::get_tracer;
use super::types::UserRegsStruct;
use crate::usercopy::write_user_value;

pub fn do_getregs(pid: u32, data: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if data == 0 {
        return Err(14);
    }
    let regs = get_tracee_regs(pid)?;
    write_user_value(data, &regs).map_err(|_| 14)
}

pub fn do_setregs(pid: u32, data: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if data == 0 {
        return Err(14);
    }
    let regs: UserRegsStruct = crate::usercopy::read_user_value(data).map_err(|_| 14)?;
    set_tracee_regs(pid, &regs)
}

pub fn get_tracee_regs(pid: u32) -> Result<UserRegsStruct, i32> {
    let ctx = crate::sched::context::get_saved_context(pid as u64).ok_or(3)?;
    Ok(UserRegsStruct {
        r15: ctx.r15,
        r14: ctx.r14,
        r13: ctx.r13,
        r12: ctx.r12,
        rbp: ctx.rbp,
        rbx: ctx.rbx,
        r11: ctx.r11,
        r10: ctx.r10,
        r9: ctx.r9,
        r8: ctx.r8,
        rax: ctx.rax,
        rcx: ctx.rcx,
        rdx: ctx.rdx,
        rsi: ctx.rsi,
        rdi: ctx.rdi,
        orig_rax: ctx.rax,
        rip: ctx.rip,
        cs: 0x33,
        eflags: ctx.rflags,
        rsp: ctx.rsp,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    })
}

pub fn set_tracee_regs(pid: u32, regs: &UserRegsStruct) -> Result<(), i32> {
    if crate::sched::context::modify_saved_context(pid as u64, |ctx| {
        ctx.r15 = regs.r15;
        ctx.r14 = regs.r14;
        ctx.r13 = regs.r13;
        ctx.r12 = regs.r12;
        ctx.rbp = regs.rbp;
        ctx.rbx = regs.rbx;
        ctx.r11 = regs.r11;
        ctx.r10 = regs.r10;
        ctx.r9 = regs.r9;
        ctx.r8 = regs.r8;
        ctx.rax = regs.rax;
        ctx.rcx = regs.rcx;
        ctx.rdx = regs.rdx;
        ctx.rsi = regs.rsi;
        ctx.rdi = regs.rdi;
        ctx.rip = regs.rip;
        ctx.rflags = regs.eflags;
        ctx.rsp = regs.rsp;
    }) {
        Ok(())
    } else {
        Err(3)
    }
}

pub fn do_getregset(pid: u32, regset_type: u32, iov_ptr: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if regset_type != 1 {
        return Err(22);
    }
    let iov: super::types::IoVec = crate::usercopy::read_user_value(iov_ptr).map_err(|_| 14)?;
    if iov.iov_len < core::mem::size_of::<UserRegsStruct>() as u64 {
        return Err(22);
    }
    let regs = get_tracee_regs(pid)?;
    write_user_value(iov.iov_base, &regs).map_err(|_| 14)
}

pub fn do_setregset(pid: u32, regset_type: u32, iov_ptr: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if regset_type != 1 {
        return Err(22);
    }
    let iov: super::types::IoVec = crate::usercopy::read_user_value(iov_ptr).map_err(|_| 14)?;
    if iov.iov_len < core::mem::size_of::<UserRegsStruct>() as u64 {
        return Err(22);
    }
    let regs: UserRegsStruct = crate::usercopy::read_user_value(iov.iov_base).map_err(|_| 14)?;
    set_tracee_regs(pid, &regs)
}
