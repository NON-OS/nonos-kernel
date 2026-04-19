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
pub enum RtldState { Uninitialized, Initializing, Ready, Finalizing }

static RTLD_STATE: Mutex<RtldState> = Mutex::new(RtldState::Uninitialized);

pub fn get_state() -> RtldState { *RTLD_STATE.lock() }

pub fn set_state(state: RtldState) { *RTLD_STATE.lock() = state; }

#[no_mangle]
pub unsafe extern "C" fn rtld_start(stack_ptr: *const usize) -> usize {
    set_state(RtldState::Initializing);
    let argc = ptr::read(stack_ptr) as i32;
    let argv = stack_ptr.add(1) as *const *const u8;
    let mut envp_idx = 1 + argc as usize + 1;
    while ptr::read(stack_ptr.add(envp_idx)) != 0 { envp_idx += 1; }
    let envp = stack_ptr.add(1 + argc as usize + 1) as *const *const u8;
    let auxv = stack_ptr.add(envp_idx + 1) as *const crate::elf::auxv::AuxEntry;
    let entry = rtld_entry(argc, argv, envp, auxv);
    set_state(RtldState::Ready);
    entry
}

pub unsafe fn rtld_entry(_argc: i32, _argv: *const *const u8, envp: *const *const u8, auxv: *const crate::elf::auxv::AuxEntry) -> usize {
    super::preload::parse_preload(envp);
    let mut phdr: *const u8 = ptr::null();
    let mut phent = 0usize;
    let mut phnum = 0usize;
    let mut entry = 0usize;
    let mut base = 0usize;
    let mut p = auxv;
    while (*p).a_type != 0 {
        match (*p).a_type as u64 {
            3 => phdr = (*p).a_val as usize as *const u8,
            4 => phent = (*p).a_val as usize,
            5 => phnum = (*p).a_val as usize,
            7 => base = (*p).a_val as usize,
            9 => entry = (*p).a_val as usize,
            _ => {}
        }
        p = p.add(1);
    }
    super::init::rtld_setup(phdr, phent, phnum, base);
    super::preload::load_preloaded();
    super::load::load_needed_recursive(base);
    super::relocate::process_all_relocs();
    super::init::call_init_functions();
    super::debug::update_debug_state(super::debug::RDebugState::Consistent);
    entry
}

#[no_mangle]
pub unsafe extern "C" fn _dl_start(stack_ptr: *const usize) -> usize {
    rtld_start(stack_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(main: usize, argc: i32, argv: *const *const u8, init: usize, fini: usize, rtld_fini: usize, stack_end: *mut u8) -> i32 {
    register_fini(fini, rtld_fini);
    if init != 0 {
        let init_fn: extern "C" fn(i32, *const *const u8, *const *const u8) = core::mem::transmute(init);
        let envp = argv.add(argc as usize + 1);
        init_fn(argc, argv, envp);
    }
    let main_fn: extern "C" fn(i32, *const *const u8, *const *const u8) -> i32 = core::mem::transmute(main);
    let envp = argv.add(argc as usize + 1);
    let result = main_fn(argc, argv, envp);
    call_fini_functions();
    if let Some(rtld) = RTLD_FINI.lock().take() {
        let rtld_fn: extern "C" fn() = core::mem::transmute(rtld);
        rtld_fn();
    }
    let _ = stack_end;
    result
}

static FINI_FUNC: Mutex<Option<usize>> = Mutex::new(None);
static RTLD_FINI: Mutex<Option<usize>> = Mutex::new(None);

fn register_fini(fini: usize, rtld_fini: usize) {
    if fini != 0 { *FINI_FUNC.lock() = Some(fini); }
    if rtld_fini != 0 { *RTLD_FINI.lock() = Some(rtld_fini); }
}

fn call_fini_functions() {
    set_state(RtldState::Finalizing);
    if let Some(fini) = FINI_FUNC.lock().take() {
        let fini_fn: extern "C" fn() = unsafe { core::mem::transmute(fini) };
        fini_fn();
    }
    unsafe { super::init::call_fini_functions(); }
}
