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

use super::types::{Elf64Symbol, ElfError};
use core::mem::size_of;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xFFF1;

pub fn resolve_symbol(base: u64, symtab: u64, strtab: u64, sym_idx: u32) -> Result<u64, ElfError> {
    if sym_idx == 0 {
        return Ok(0);
    }
    if symtab == 0 {
        return Err(ElfError::RelocationFailed);
    }
    let sym_ptr =
        (symtab + base + (sym_idx as u64) * size_of::<Elf64Symbol>() as u64) as *const Elf64Symbol;
    let sym = unsafe { &*sym_ptr };
    let binding = sym.st_info >> 4;
    if sym.st_shndx == SHN_UNDEF {
        if binding == STB_WEAK {
            return Ok(0);
        }
        if binding == STB_LOCAL {
            return Err(ElfError::RelocationFailed);
        }
        let name = get_symbol_name(base, strtab, sym.st_name);
        if binding == STB_GLOBAL {
            if let Some(addr) = lookup_kernel_symbol(&name) {
                return Ok(addr);
            }
        }
        return Err(ElfError::RelocationFailed);
    }
    if sym.st_shndx == SHN_ABS {
        return Ok(sym.st_value);
    }
    Ok(sym.st_value + base)
}

fn get_symbol_name(base: u64, strtab: u64, name_off: u32) -> alloc::string::String {
    if strtab == 0 {
        return alloc::string::String::new();
    }
    let ptr = (strtab + base + name_off as u64) as *const u8;
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 && len < 256 {
        len += 1;
    }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    alloc::string::String::from_utf8_lossy(slice).into_owned()
}

// LIMIT: the kernel no longer hands user programs the addresses of
// kernel-resident libc functions. That door collapsed the user/kernel
// spatial boundary (user code executing in kernel pages) and is being
// retired in favor of a userspace libc capsule. Programs that
// statically link their own libc keep working; programs that need a
// dynamic libc must arrive via rtld with a real libc.so to load. No
// libc.so artifact exists yet; providing one is the next relocation
// slice. The libc Rust source still compiles into the kernel image
// pending its final removal, but the symbol-resolution path here no
// longer surfaces it to user programs.
fn lookup_kernel_symbol(name: &str) -> Option<u64> {
    match name {
        // crt placeholders that programs reference but expect to be
        // weak / no-op. Returning 0 lets the loader proceed.
        "__gmon_start__" | "_ITM_deregisterTMCloneTable" | "_ITM_registerTMCloneTable" => Some(0),
        _ => crate::elf::rtld::resolve_global_symbol(name).map(|r| r.address as u64),
    }
}

pub fn get_symbol_by_index(
    base: u64,
    symtab: u64,
    strtab: u64,
    idx: u32,
) -> Option<(alloc::string::String, u64)> {
    if symtab == 0 || idx == 0 {
        return None;
    }
    let sym_ptr =
        (symtab + base + (idx as u64) * size_of::<Elf64Symbol>() as u64) as *const Elf64Symbol;
    let sym = unsafe { &*sym_ptr };
    let name = get_symbol_name(base, strtab, sym.st_name);
    let addr = if sym.st_shndx == SHN_ABS { sym.st_value } else { sym.st_value + base };
    Some((name, addr))
}
