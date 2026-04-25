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
use alloc::string::String;

#[derive(Debug, Clone)]
pub struct SymbolResolution {
    pub name: String,
    pub address: usize,
    pub size: usize,
    pub object_base: usize,
    pub bind: u8,
    pub sym_type: u8,
}

pub fn resolve_symbol(name: &str, exclude_base: Option<usize>) -> Option<SymbolResolution> {
    let objects = super::load::get_loaded_objects();
    for obj in &objects {
        if let Some(excl) = exclude_base {
            if obj.base == excl {
                continue;
            }
        }
        if let Some(sym) = lookup_in_object(obj, name) {
            return Some(sym);
        }
    }
    None
}

fn lookup_in_object(obj: &super::load::LoadedObject, name: &str) -> Option<SymbolResolution> {
    if obj.dynamic == 0 {
        return None;
    }
    let dyn_info = parse_dynamic_section(obj.dynamic, obj.base);
    if dyn_info.symtab == 0 || dyn_info.strtab == 0 {
        return None;
    }
    if dyn_info.gnu_hash != 0 {
        return gnu_hash_lookup(
            dyn_info.gnu_hash,
            dyn_info.strtab,
            dyn_info.symtab,
            name,
            obj.base,
        );
    }
    if dyn_info.sysv_hash != 0 {
        return sysv_hash_lookup(
            dyn_info.sysv_hash,
            dyn_info.strtab,
            dyn_info.symtab,
            name,
            obj.base,
        );
    }
    linear_symbol_search(dyn_info.symtab, dyn_info.strtab, name, obj.base)
}

struct DynamicInfo {
    symtab: usize,
    strtab: usize,
    strsz: usize,
    gnu_hash: usize,
    sysv_hash: usize,
}

fn parse_dynamic_section(dynamic: usize, base: usize) -> DynamicInfo {
    let mut info = DynamicInfo { symtab: 0, strtab: 0, strsz: 0, gnu_hash: 0, sysv_hash: 0 };
    let mut ptr = dynamic;
    loop {
        let tag = unsafe { *(ptr as *const i64) };
        let val = unsafe { *((ptr + 8) as *const u64) };
        match tag {
            0 => break,
            5 => info.strtab = base + val as usize,
            6 => info.symtab = base + val as usize,
            10 => info.strsz = val as usize,
            4 => info.sysv_hash = base + val as usize,
            0x6ffffef5 => info.gnu_hash = base + val as usize,
            _ => {}
        }
        ptr += 16;
    }
    info
}

fn linear_symbol_search(
    symtab: usize,
    strtab: usize,
    name: &str,
    base: usize,
) -> Option<SymbolResolution> {
    let strtab_slice = unsafe { core::slice::from_raw_parts(strtab as *const u8, 0x10000) };
    for i in 1..4096usize {
        let sym = unsafe { &*((symtab + i * 24) as *const crate::elf::types::Symbol) };
        if sym.st_name == 0 {
            continue;
        }
        let sym_name = symbol_name(strtab_slice, sym);
        if sym_name == name && sym.st_shndx != 0 {
            return Some(SymbolResolution {
                name: String::from(name),
                address: base + sym.st_value as usize,
                size: sym.st_size as usize,
                object_base: base,
                bind: (sym.st_info >> 4) & 0xf,
                sym_type: sym.st_info & 0xf,
            });
        }
    }
    None
}

pub fn resolve_plt(obj_base: usize, reloc_idx: usize) -> usize {
    let objects = super::load::get_loaded_objects();
    let obj = match objects.iter().find(|o| o.base == obj_base) {
        Some(o) => o,
        None => return 0,
    };
    if obj.dynamic == 0 {
        return 0;
    }
    let dyn_info = parse_dynamic_section(obj.dynamic, obj.base);
    if dyn_info.symtab == 0 || dyn_info.strtab == 0 {
        return 0;
    }
    let jmprel = get_jmprel(obj.dynamic, obj.base);
    if jmprel == 0 {
        return 0;
    }
    let rela_addr = jmprel + reloc_idx * 24;
    let rela = unsafe { &*(rela_addr as *const crate::elf::types::RelaEntry) };
    let sym_idx = (rela.r_info >> 32) as usize;
    if sym_idx == 0 {
        return 0;
    }
    let sym = unsafe { &*((dyn_info.symtab + sym_idx * 24) as *const crate::elf::types::Symbol) };
    if sym.st_shndx != 0 {
        return obj.base + sym.st_value as usize;
    }
    let strtab = unsafe { core::slice::from_raw_parts(dyn_info.strtab as *const u8, 0x10000) };
    let name = symbol_name(strtab, sym);
    if name.is_empty() {
        return 0;
    }
    resolve_symbol(name, Some(obj.base)).map(|s| s.address).unwrap_or(0)
}

fn get_jmprel(dynamic: usize, base: usize) -> usize {
    let mut ptr = dynamic;
    loop {
        let tag = unsafe { *(ptr as *const i64) };
        let val = unsafe { *((ptr + 8) as *const u64) };
        match tag {
            0 => break,
            23 => return base + val as usize,
            _ => {}
        }
        ptr += 16;
    }
    0
}

pub fn resolve_symbol_in_object(
    obj: &super::load::LoadedObject,
    name: &str,
) -> Option<SymbolResolution> {
    lookup_in_object(obj, name)
}

pub fn resolve_weak_symbol(name: &str) -> Option<SymbolResolution> {
    let sym = resolve_symbol(name, None)?;
    if sym.bind == 2 {
        Some(sym)
    } else {
        None
    }
}

pub fn resolve_global_symbol(name: &str) -> Option<SymbolResolution> {
    let sym = resolve_symbol(name, None)?;
    if sym.bind == 1 {
        Some(sym)
    } else {
        None
    }
}

pub fn resolve_ifunc(addr: usize) -> usize {
    let resolver: extern "C" fn() -> usize = unsafe { core::mem::transmute(addr) };
    resolver()
}

pub fn get_symbol_value(sym: &crate::elf::types::Symbol, base: usize) -> usize {
    if sym.st_shndx == 0 {
        0
    } else {
        base + sym.st_value as usize
    }
}

pub fn symbol_name<'a>(strtab: &'a [u8], sym: &crate::elf::types::Symbol) -> &'a str {
    let start = sym.st_name as usize;
    let end =
        strtab[start..].iter().position(|&c| c == 0).map(|p| start + p).unwrap_or(strtab.len());
    core::str::from_utf8(&strtab[start..end]).unwrap_or("")
}

pub fn gnu_hash_lookup(
    hash_table: usize,
    strtab: usize,
    symtab: usize,
    name: &str,
    base: usize,
) -> Option<SymbolResolution> {
    let nbuckets = unsafe { *(hash_table as *const u32) } as usize;
    let symoffset = unsafe { *((hash_table + 4) as *const u32) } as usize;
    let bloom_size = unsafe { *((hash_table + 8) as *const u32) } as usize;
    let bloom_shift = unsafe { *((hash_table + 12) as *const u32) };
    let bloom_ptr = hash_table + 16;
    let buckets_ptr = bloom_ptr + bloom_size * 8;
    let chains_ptr = buckets_ptr + nbuckets * 4;
    let hash = gnu_hash(name);
    let bloom_word =
        unsafe { *((bloom_ptr + ((hash as usize / 64) % bloom_size) * 8) as *const u64) };
    let mask = (1u64 << (hash % 64)) | (1u64 << ((hash >> bloom_shift) % 64));
    if (bloom_word & mask) != mask {
        return None;
    }
    let bucket_idx = (hash as usize) % nbuckets;
    let mut sym_idx = unsafe { *((buckets_ptr + bucket_idx * 4) as *const u32) } as usize;
    if sym_idx == 0 {
        return None;
    }
    let strtab_slice = unsafe { core::slice::from_raw_parts(strtab as *const u8, 0x10000) };
    loop {
        let sym = unsafe { &*((symtab + sym_idx * 24) as *const crate::elf::types::Symbol) };
        let chain_val = unsafe { *((chains_ptr + (sym_idx - symoffset) * 4) as *const u32) };
        if (chain_val | 1) == (hash | 1) {
            let sym_name = symbol_name(strtab_slice, sym);
            if sym_name == name && sym.st_shndx != 0 {
                return Some(SymbolResolution {
                    name: String::from(name),
                    address: base + sym.st_value as usize,
                    size: sym.st_size as usize,
                    object_base: base,
                    bind: (sym.st_info >> 4) & 0xf,
                    sym_type: sym.st_info & 0xf,
                });
            }
        }
        if (chain_val & 1) != 0 {
            break;
        }
        sym_idx += 1;
    }
    None
}

fn gnu_hash(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for c in name.bytes() {
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

pub fn sysv_hash_lookup(
    hash_table: usize,
    strtab: usize,
    symtab: usize,
    name: &str,
    base: usize,
) -> Option<SymbolResolution> {
    let nbucket = unsafe { *(hash_table as *const u32) } as usize;
    let buckets = hash_table + 8;
    let chains = buckets + nbucket * 4;
    let hash = elf_hash(name);
    let mut idx = unsafe { *((buckets + (hash % nbucket) * 4) as *const u32) } as usize;
    let strtab_slice = unsafe { core::slice::from_raw_parts(strtab as *const u8, 0x10000) };
    while idx != 0 {
        let sym = unsafe { &*((symtab + idx * 24) as *const crate::elf::types::Symbol) };
        let sym_name = symbol_name(strtab_slice, sym);
        if sym_name == name && sym.st_shndx != 0 {
            return Some(SymbolResolution {
                name: String::from(name),
                address: base + sym.st_value as usize,
                size: sym.st_size as usize,
                object_base: base,
                bind: (sym.st_info >> 4) & 0xf,
                sym_type: sym.st_info & 0xf,
            });
        }
        idx = unsafe { *((chains + idx * 4) as *const u32) } as usize;
    }
    None
}

fn elf_hash(name: &str) -> usize {
    let mut h: u32 = 0;
    for c in name.bytes() {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf0000000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h as usize
}
