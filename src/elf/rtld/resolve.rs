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
        if let Some(excl) = exclude_base { if obj.base == excl { continue; } }
        if let Some(sym) = lookup_in_object(obj, name) { return Some(sym); }
    }
    None
}

fn lookup_in_object(obj: &super::load::LoadedObject, name: &str) -> Option<SymbolResolution> {
    let _ = (obj, name);
    None
}

pub fn resolve_plt(obj_base: usize, reloc_idx: usize) -> usize {
    let objects = super::load::get_loaded_objects();
    let obj = match objects.iter().find(|o| o.base == obj_base) {
        Some(o) => o,
        None => return 0,
    };
    let _ = (obj, reloc_idx);
    0
}

pub fn resolve_symbol_in_object(obj: &super::load::LoadedObject, name: &str) -> Option<SymbolResolution> {
    lookup_in_object(obj, name)
}

pub fn resolve_weak_symbol(name: &str) -> Option<SymbolResolution> {
    let sym = resolve_symbol(name, None)?;
    if sym.bind == 2 { Some(sym) } else { None }
}

pub fn resolve_global_symbol(name: &str) -> Option<SymbolResolution> {
    let sym = resolve_symbol(name, None)?;
    if sym.bind == 1 { Some(sym) } else { None }
}

pub fn resolve_ifunc(addr: usize) -> usize {
    let resolver: extern "C" fn() -> usize = unsafe { core::mem::transmute(addr) };
    resolver()
}

pub fn get_symbol_value(sym: &crate::elf::types::Symbol, base: usize) -> usize {
    if sym.st_shndx == 0 { 0 } else { base + sym.st_value as usize }
}

pub fn symbol_name<'a>(strtab: &'a [u8], sym: &crate::elf::types::Symbol) -> &'a str {
    let start = sym.st_name as usize;
    let end = strtab[start..].iter().position(|&c| c == 0).map(|p| start + p).unwrap_or(strtab.len());
    core::str::from_utf8(&strtab[start..end]).unwrap_or("")
}

pub fn gnu_hash_lookup(hash_table: usize, strtab: usize, symtab: usize, name: &str, base: usize) -> Option<SymbolResolution> {
    let _ = (hash_table, strtab, symtab, name, base);
    None
}

pub fn sysv_hash_lookup(hash_table: usize, strtab: usize, symtab: usize, name: &str, base: usize) -> Option<SymbolResolution> {
    let _ = (hash_table, strtab, symtab, name, base);
    None
}
