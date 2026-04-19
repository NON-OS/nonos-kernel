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
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct RtldConfig {
    pub bind_now: bool,
    pub lazy: bool,
    pub nodelete: bool,
    pub noload: bool,
    pub deepbind: bool,
}

impl Default for RtldConfig {
    fn default() -> Self { Self { bind_now: false, lazy: true, nodelete: false, noload: false, deepbind: false } }
}

static CONFIG: Mutex<RtldConfig> = Mutex::new(RtldConfig { bind_now: false, lazy: true, nodelete: false, noload: false, deepbind: false });
static INIT_FUNCTIONS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

pub fn rtld_init() {
    super::search::init_search_paths();
    super::debug::init_r_debug();
}

pub unsafe fn rtld_setup(phdr: *const u8, phent: usize, phnum: usize, base: usize) {
    rtld_init();
    let mut dynamic = core::ptr::null::<u8>();
    for i in 0..phnum {
        let ph = phdr.add(i * phent) as *const crate::elf::types::ProgramHeader;
        if (*ph).p_type == 2 { dynamic = (base + (*ph).p_vaddr as usize) as *const u8; break; }
    }
    if !dynamic.is_null() { parse_dynamic(dynamic, base); }
    super::tls::init_static_tls();
}

unsafe fn parse_dynamic(dynamic: *const u8, base: usize) {
    let mut init = 0usize;
    let mut init_array = 0usize;
    let mut init_arraysz = 0usize;
    let mut p = dynamic as *const crate::elf::types::DynamicEntry;
    while (*p).d_tag != 0 {
        match (*p).d_tag as u64 {
            12 => { init = base + (*p).value as usize; }
            25 => { init_array = base + (*p).value as usize; }
            27 => { init_arraysz = (*p).value as usize; }
            30 => { CONFIG.lock().bind_now = true; }
            _ => {}
        }
        p = p.add(1);
    }
    if init != 0 { INIT_FUNCTIONS.lock().push((init, 0)); }
    if init_array != 0 && init_arraysz > 0 { INIT_FUNCTIONS.lock().push((init_array, init_arraysz)); }
}

pub unsafe fn call_init_functions() {
    let funcs = INIT_FUNCTIONS.lock().clone();
    for (addr, size) in funcs {
        if size == 0 {
            let f: extern "C" fn() = core::mem::transmute(addr);
            f();
        } else {
            let count = size / 8;
            let array = addr as *const usize;
            for i in 0..count {
                let fn_addr = core::ptr::read(array.add(i));
                if fn_addr != 0 && fn_addr != usize::MAX {
                    let f: extern "C" fn() = core::mem::transmute(fn_addr);
                    f();
                }
            }
        }
    }
}

pub fn get_config() -> RtldConfig { CONFIG.lock().clone() }

pub fn set_bind_now(val: bool) { CONFIG.lock().bind_now = val; }

static FINI_FUNCTIONS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

pub fn register_fini(fini: usize, fini_array: usize, fini_arraysz: usize) {
    if fini != 0 { FINI_FUNCTIONS.lock().push((fini, 0)); }
    if fini_array != 0 && fini_arraysz > 0 { FINI_FUNCTIONS.lock().push((fini_array, fini_arraysz)); }
}

pub unsafe fn call_fini_functions() {
    let funcs: Vec<_> = FINI_FUNCTIONS.lock().drain(..).rev().collect();
    for (addr, size) in funcs {
        if size == 0 {
            let f: extern "C" fn() = core::mem::transmute(addr);
            f();
        } else {
            let count = size / 8;
            let array = addr as *const usize;
            for i in (0..count).rev() {
                let fn_addr = core::ptr::read(array.add(i));
                if fn_addr != 0 && fn_addr != usize::MAX {
                    let f: extern "C" fn() = core::mem::transmute(fn_addr);
                    f();
                }
            }
        }
    }
}
