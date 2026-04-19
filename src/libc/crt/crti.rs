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

pub type InitFn = extern "C" fn();
pub type FiniFn = extern "C" fn();

static mut INIT_ARRAY_START: *const InitFn = ptr::null();
static mut INIT_ARRAY_END: *const InitFn = ptr::null();
static mut FINI_ARRAY_START: *const FiniFn = ptr::null();
static mut FINI_ARRAY_END: *const FiniFn = ptr::null();

pub fn set_init_array(start: *const InitFn, end: *const InitFn) {
    unsafe { INIT_ARRAY_START = start; INIT_ARRAY_END = end; }
}

pub fn set_fini_array(start: *const FiniFn, end: *const FiniFn) {
    unsafe { FINI_ARRAY_START = start; FINI_ARRAY_END = end; }
}

pub fn crti_init() {
    init_array_call();
}

pub fn crti_fini() {
    fini_array_call();
}

pub fn init_array_call() {
    unsafe {
        if INIT_ARRAY_START.is_null() || INIT_ARRAY_END.is_null() { return; }
        let mut p = INIT_ARRAY_START;
        while p < INIT_ARRAY_END {
            let f = ptr::read(p);
            if (f as usize) != 0 && (f as usize) != usize::MAX { f(); }
            p = p.add(1);
        }
    }
}

pub fn fini_array_call() {
    unsafe {
        if FINI_ARRAY_START.is_null() || FINI_ARRAY_END.is_null() { return; }
        let count = FINI_ARRAY_END.offset_from(FINI_ARRAY_START) as usize;
        for i in (0..count).rev() {
            let f = ptr::read(FINI_ARRAY_START.add(i));
            if (f as usize) != 0 && (f as usize) != usize::MAX { f(); }
        }
    }
}

pub fn register_atexit(f: FiniFn) {
    crate::libc::stdlib::atexit_register(f);
}

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    crate::sys::serial::println(b"*** stack smashing detected ***");
    crate::syscall::sys_exit(134);
}

#[no_mangle]
pub static __stack_chk_guard: u64 = 0x595e9fbd94fda766;

type CxaFn = extern "C" fn(*mut u8);
static mut CXA_ATEXIT_FUNCS: [(CxaFn, *mut u8, *mut u8); 32] = [(dummy_cxa, core::ptr::null_mut(), core::ptr::null_mut()); 32];
static mut CXA_ATEXIT_COUNT: usize = 0;
extern "C" fn dummy_cxa(_: *mut u8) {}

#[no_mangle]
pub unsafe extern "C" fn __cxa_atexit(f: CxaFn, arg: *mut u8, dso: *mut u8) -> i32 {
    if CXA_ATEXIT_COUNT >= 32 { return -1; }
    CXA_ATEXIT_FUNCS[CXA_ATEXIT_COUNT] = (f, arg, dso);
    CXA_ATEXIT_COUNT += 1;
    0
}

pub fn run_cxa_atexit_funcs() {
    unsafe {
        while CXA_ATEXIT_COUNT > 0 {
            CXA_ATEXIT_COUNT -= 1;
            let (f, arg, _) = CXA_ATEXIT_FUNCS[CXA_ATEXIT_COUNT];
            f(arg);
        }
    }
}
