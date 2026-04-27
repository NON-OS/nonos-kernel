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

pub fn do_peekdata(pid: u32, addr: u64) -> Result<u64, i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    read_tracee_memory(pid, addr)
}

pub fn do_pokedata(pid: u32, addr: u64, data: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    write_tracee_memory(pid, addr, data)
}

pub fn do_peektext(pid: u32, addr: u64) -> Result<u64, i32> {
    do_peekdata(pid, addr)
}

pub fn do_poketext(pid: u32, addr: u64, data: u64) -> Result<(), i32> {
    do_pokedata(pid, addr, data)
}

fn read_tracee_memory(pid: u32, addr: u64) -> Result<u64, i32> {
    let cr3 = crate::syscall::process_vm::access::get_target_cr3(pid).ok_or(3)?;
    let phys =
        crate::syscall::process_vm::translate::translate_with_cr3(cr3, addr as usize).ok_or(14)?;
    let ptr = phys as *const u64;
    Ok(unsafe { *ptr })
}

fn write_tracee_memory(pid: u32, addr: u64, data: u64) -> Result<(), i32> {
    let cr3 = crate::syscall::process_vm::access::get_target_cr3(pid).ok_or(3)?;
    let phys =
        crate::syscall::process_vm::translate::translate_with_cr3(cr3, addr as usize).ok_or(14)?;
    let ptr = phys as *mut u64;
    unsafe {
        *ptr = data;
    }
    Ok(())
}

pub fn do_peekuser(pid: u32, offset: u64) -> Result<u64, i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if offset >= 216 {
        return Err(22);
    }
    let regs = super::regs::get_tracee_regs(pid)?;
    let regs_bytes = unsafe { core::slice::from_raw_parts(&regs as *const _ as *const u8, 216) };
    let val = u64::from_ne_bytes([
        regs_bytes[offset as usize],
        regs_bytes.get(offset as usize + 1).copied().unwrap_or(0),
        regs_bytes.get(offset as usize + 2).copied().unwrap_or(0),
        regs_bytes.get(offset as usize + 3).copied().unwrap_or(0),
        regs_bytes.get(offset as usize + 4).copied().unwrap_or(0),
        regs_bytes.get(offset as usize + 5).copied().unwrap_or(0),
        regs_bytes.get(offset as usize + 6).copied().unwrap_or(0),
        regs_bytes.get(offset as usize + 7).copied().unwrap_or(0),
    ]);
    Ok(val)
}

pub fn do_pokeuser(pid: u32, offset: u64, data: u64) -> Result<(), i32> {
    let tracer = crate::process::current_pid().ok_or(3)?;
    if get_tracer(pid) != Some(tracer) {
        return Err(3);
    }
    if offset >= 216 || offset % 8 != 0 {
        return Err(22);
    }
    let mut regs = super::regs::get_tracee_regs(pid)?;
    let regs_bytes =
        unsafe { core::slice::from_raw_parts_mut(&mut regs as *mut _ as *mut u8, 216) };
    let data_bytes = data.to_ne_bytes();
    for i in 0..8 {
        regs_bytes[offset as usize + i] = data_bytes[i];
    }
    super::regs::set_tracee_regs(pid, &regs)
}
