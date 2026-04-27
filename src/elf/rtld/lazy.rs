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
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LazyBindingState {
    Disabled,
    Enabled,
    Forced,
}

static LAZY_STATE: Mutex<LazyBindingState> = Mutex::new(LazyBindingState::Enabled);

pub fn get_lazy_state() -> LazyBindingState {
    *LAZY_STATE.lock()
}

pub fn set_lazy_state(state: LazyBindingState) {
    *LAZY_STATE.lock() = state;
}

pub fn lazy_bind(obj_base: usize, reloc_idx: usize) -> usize {
    let objects = super::load::get_loaded_objects();
    let obj = match objects.iter().find(|o| o.base == obj_base) {
        Some(o) => o,
        None => return 0,
    };
    let ctx = build_lazy_context(obj);
    let rela_addr = ctx.jmprel + reloc_idx * 24;
    let rela = unsafe { &*(rela_addr as *const crate::elf::types::RelaEntry) };
    let sym_idx = (rela.r_info >> 32) as usize;
    let reloc_addr = obj_base + rela.r_offset as usize;
    let sym_value = resolve_lazy_symbol(&ctx, sym_idx);
    unsafe {
        ptr::write(reloc_addr as *mut usize, sym_value);
    }
    sym_value
}

fn build_lazy_context(obj: &super::load::LoadedObject) -> LazyContext {
    let mut ctx = LazyContext { base: obj.base, symtab: 0, strtab: 0, jmprel: 0, pltrelsz: 0 };
    if obj.dynamic != 0 {
        let mut dyn_ptr = obj.dynamic as *const crate::elf::types::DynamicEntry;
        unsafe {
            while (*dyn_ptr).d_tag != 0 {
                match (*dyn_ptr).d_tag {
                    6 => ctx.symtab = obj.base + (*dyn_ptr).value as usize,
                    5 => ctx.strtab = obj.base + (*dyn_ptr).value as usize,
                    23 => ctx.jmprel = obj.base + (*dyn_ptr).value as usize,
                    2 => ctx.pltrelsz = (*dyn_ptr).value as usize,
                    _ => {}
                }
                dyn_ptr = dyn_ptr.add(1);
            }
        }
    }
    ctx
}

struct LazyContext {
    base: usize,
    symtab: usize,
    strtab: usize,
    jmprel: usize,
    pltrelsz: usize,
}

fn resolve_lazy_symbol(ctx: &LazyContext, sym_idx: usize) -> usize {
    if ctx.symtab == 0 || ctx.strtab == 0 {
        return 0;
    }
    let sym = unsafe { &*((ctx.symtab + sym_idx * 24) as *const crate::elf::types::Symbol) };
    if sym.st_value != 0 {
        return ctx.base + sym.st_value as usize;
    }
    let name_ptr = (ctx.strtab + sym.st_name as usize) as *const u8;
    let name = unsafe {
        let mut len = 0;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(name_ptr, len))
    };
    super::resolve::resolve_symbol(name, Some(ctx.base)).map(|r| r.address).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn plt_resolver(obj_base: usize, reloc_idx: usize) -> usize {
    lazy_bind(obj_base, reloc_idx)
}

#[no_mangle]
pub unsafe extern "C" fn _dl_runtime_resolve(link_map: usize, reloc_idx: usize) -> usize {
    lazy_bind(link_map, reloc_idx)
}

pub fn setup_plt_resolver(obj: &super::load::LoadedObject, got_plt: usize) {
    if got_plt == 0 {
        return;
    }
    unsafe {
        ptr::write((got_plt + 8) as *mut usize, obj.base);
        ptr::write((got_plt + 16) as *mut usize, plt_resolver as *const () as usize);
    }
}

pub fn force_bind_now() {
    set_lazy_state(LazyBindingState::Disabled);
    let objects = super::load::get_loaded_objects();
    for obj in &objects {
        if obj.dynamic == 0 {
            continue;
        }
        let ctx = build_lazy_context(&obj);
        if ctx.jmprel != 0 && ctx.pltrelsz > 0 {
            let count = ctx.pltrelsz / 24;
            for i in 0..count {
                lazy_bind(obj.base, i);
            }
        }
    }
}
