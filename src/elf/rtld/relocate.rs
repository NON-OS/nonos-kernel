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

use core::ptr;

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_IRELATIVE: u32 = 37;

#[derive(Debug, Clone)]
pub struct RelocationContext {
    pub base: usize,
    pub symtab: usize,
    pub strtab: usize,
    pub rela: usize,
    pub relasz: usize,
    pub pltrel: usize,
    pub pltrelsz: usize,
    pub jmprel: usize,
}

pub fn process_relocs(ctx: &RelocationContext, lazy: bool) {
    if ctx.rela != 0 && ctx.relasz > 0 {
        let count = ctx.relasz / 24;
        for i in 0..count { process_rela(ctx, ctx.rela + i * 24); }
    }
    if !lazy && ctx.jmprel != 0 && ctx.pltrelsz > 0 {
        let count = ctx.pltrelsz / 24;
        for i in 0..count { process_rela(ctx, ctx.jmprel + i * 24); }
    }
}

fn process_rela(ctx: &RelocationContext, addr: usize) {
    let rela = unsafe { &*(addr as *const crate::elf::types::RelaEntry) };
    let reloc_type = (rela.r_info & 0xffffffff) as u32;
    let sym_idx = (rela.r_info >> 32) as usize;
    let reloc_addr = ctx.base + rela.r_offset as usize;
    apply_relocation(reloc_type, reloc_addr, ctx.base, sym_idx, rela.r_addend as i64, ctx);
}

pub fn apply_relocation(reloc_type: u32, addr: usize, base: usize, sym_idx: usize, addend: i64, ctx: &RelocationContext) {
    let sym_value = if sym_idx != 0 { resolve_symbol_value(ctx, sym_idx) } else { 0 };
    match reloc_type {
        R_X86_64_NONE => {}
        R_X86_64_64 => unsafe { ptr::write(addr as *mut u64, (sym_value as i64 + addend) as u64); }
        R_X86_64_PC32 => unsafe {
            let val = (sym_value as i64 + addend - addr as i64) as i32;
            ptr::write(addr as *mut i32, val);
        }
        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => unsafe { ptr::write(addr as *mut u64, sym_value as u64); }
        R_X86_64_RELATIVE => unsafe { ptr::write(addr as *mut u64, (base as i64 + addend) as u64); }
        R_X86_64_COPY => {
            let size = get_symbol_size(ctx, sym_idx);
            unsafe { ptr::copy_nonoverlapping(sym_value as *const u8, addr as *mut u8, size); }
        }
        R_X86_64_TPOFF64 => unsafe { ptr::write(addr as *mut u64, sym_value as u64); }
        R_X86_64_IRELATIVE => {
            let resolver: extern "C" fn() -> usize = unsafe { core::mem::transmute(base + addend as usize) };
            unsafe { ptr::write(addr as *mut usize, resolver()); }
        }
        _ => {}
    }
}

fn resolve_symbol_value(ctx: &RelocationContext, sym_idx: usize) -> usize {
    if ctx.symtab == 0 || ctx.strtab == 0 { return 0; }
    let sym = unsafe { &*((ctx.symtab + sym_idx * 24) as *const crate::elf::types::Symbol) };
    if sym.st_shndx != 0 {
        return ctx.base + sym.st_value as usize;
    }
    let strtab_slice = unsafe { core::slice::from_raw_parts(ctx.strtab as *const u8, 0x10000) };
    let name = super::resolve::symbol_name(strtab_slice, sym);
    if name.is_empty() { return 0; }
    super::resolve::resolve_symbol(name, Some(ctx.base))
        .map(|s| s.address)
        .unwrap_or(0)
}

fn get_symbol_size(ctx: &RelocationContext, sym_idx: usize) -> usize {
    if ctx.symtab == 0 { return 0; }
    let sym = unsafe { &*((ctx.symtab + sym_idx * 24) as *const crate::elf::types::Symbol) };
    sym.st_size as usize
}

pub fn process_all_relocs() {
    let objects = super::load::get_loaded_objects();
    let lazy = super::init::get_config().lazy;
    for obj in &objects {
        if obj.dynamic == 0 { continue; }
        let ctx = build_reloc_context(obj);
        process_relocs(&ctx, lazy);
    }
}

fn build_reloc_context(obj: &super::load::LoadedObject) -> RelocationContext {
    let mut ctx = RelocationContext {
        base: obj.base, symtab: 0, strtab: 0, rela: 0, relasz: 0, pltrel: 0, pltrelsz: 0, jmprel: 0
    };
    if obj.dynamic == 0 { return ctx; }
    let mut ptr = obj.dynamic;
    loop {
        let tag = unsafe { *(ptr as *const i64) };
        let val = unsafe { *((ptr + 8) as *const u64) };
        match tag {
            0 => break,
            5 => ctx.strtab = obj.base + val as usize,
            6 => ctx.symtab = obj.base + val as usize,
            7 => ctx.rela = obj.base + val as usize,
            8 => ctx.relasz = val as usize,
            20 => ctx.pltrel = val as usize,
            2 => ctx.pltrelsz = val as usize,
            23 => ctx.jmprel = obj.base + val as usize,
            _ => {}
        }
        ptr += 16;
    }
    ctx
}
