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
