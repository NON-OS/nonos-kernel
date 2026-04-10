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

use core::mem::size_of;
use super::types::{Elf64Symbol, ElfError};

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xFFF1;

pub fn resolve_symbol(base: u64, symtab: u64, strtab: u64, sym_idx: u32) -> Result<u64, ElfError> {
    if sym_idx == 0 { return Ok(0); }
    if symtab == 0 { return Err(ElfError::RelocationFailed); }
    let sym_ptr = (symtab + base + (sym_idx as u64) * size_of::<Elf64Symbol>() as u64) as *const Elf64Symbol;
    let sym = unsafe { &*sym_ptr };
    let binding = sym.st_info >> 4;
    if sym.st_shndx == SHN_UNDEF {
        if binding == STB_WEAK { return Ok(0); }
        if binding == STB_LOCAL { return Err(ElfError::RelocationFailed); }
        let name = get_symbol_name(base, strtab, sym.st_name);
        if binding == STB_GLOBAL {
            if let Some(addr) = lookup_kernel_symbol(&name) { return Ok(addr); }
        }
        return Err(ElfError::RelocationFailed);
    }
    if sym.st_shndx == SHN_ABS { return Ok(sym.st_value); }
    Ok(sym.st_value + base)
}

fn get_symbol_name(base: u64, strtab: u64, name_off: u32) -> alloc::string::String {
    if strtab == 0 { return alloc::string::String::new(); }
    let ptr = (strtab + base + name_off as u64) as *const u8;
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 && len < 256 { len += 1; }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    alloc::string::String::from_utf8_lossy(slice).into_owned()
}

fn lookup_kernel_symbol(name: &str) -> Option<u64> {
    match name {
        "__libc_start_main" => Some(crate::libc::get_libc_start_main_addr()),
        "exit" | "_exit" => Some(crate::libc::get_exit_addr()),
        "write" => Some(crate::libc::get_write_addr()),
        "read" => Some(crate::libc::get_read_addr()),
        "open" => Some(crate::libc::get_open_addr()),
        "close" => Some(crate::libc::get_close_addr()),
        "malloc" => Some(crate::libc::get_malloc_addr()),
        "free" => Some(crate::libc::get_free_addr()),
        "mmap" => Some(crate::libc::get_mmap_addr()),
        "munmap" => Some(crate::libc::get_munmap_addr()),
        "brk" | "sbrk" => Some(crate::libc::get_brk_addr()),
        "getpid" => Some(crate::libc::get_getpid_addr()),
        "fork" => Some(crate::libc::get_fork_addr()),
        "execve" => Some(crate::libc::get_execve_addr()),
        "waitpid" | "wait" => Some(crate::libc::get_waitpid_addr()),
        "ioctl" => Some(crate::libc::get_ioctl_addr()),
        "printf" | "__printf_chk" => Some(crate::libc::get_printf_addr()),
        "puts" => Some(crate::libc::get_puts_addr()),
        "fopen" => Some(crate::libc::get_fopen_addr()),
        "fclose" => Some(crate::libc::get_fclose_addr()),
        "fread" => Some(crate::libc::get_fread_addr()),
        "fwrite" => Some(crate::libc::get_fwrite_addr()),
        "__stack_chk_fail" => Some(crate::libc::get_stack_chk_fail_addr()),
        "__cxa_atexit" => Some(crate::libc::get_cxa_atexit_addr()),
        "__gmon_start__" | "_ITM_deregisterTMCloneTable" | "_ITM_registerTMCloneTable" => Some(0),
        _ => crate::elf::rtld::resolve_global_symbol(name).map(|r| r.address as u64),
    }
}

pub fn get_symbol_by_index(base: u64, symtab: u64, strtab: u64, idx: u32) -> Option<(alloc::string::String, u64)> {
    if symtab == 0 || idx == 0 { return None; }
    let sym_ptr = (symtab + base + (idx as u64) * size_of::<Elf64Symbol>() as u64) as *const Elf64Symbol;
    let sym = unsafe { &*sym_ptr };
    let name = get_symbol_name(base, strtab, sym.st_name);
    let addr = if sym.st_shndx == SHN_ABS { sym.st_value } else { sym.st_value + base };
    Some((name, addr))
}
