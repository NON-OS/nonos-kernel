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

use spin::Mutex;

pub type AtexitFn = extern "C" fn();

const MAX_ATEXIT: usize = 32;
static ATEXIT_FUNCS: Mutex<[Option<AtexitFn>; MAX_ATEXIT]> = Mutex::new([None; MAX_ATEXIT]);
static ATEXIT_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[no_mangle]
pub extern "C" fn exit(status: i32) -> ! {
    run_atexit_handlers();
    crate::libc::crt::crti::crti_fini();
    crate::libc::unistd::_exit(status);
}

#[no_mangle]
pub extern "C" fn _Exit(status: i32) -> ! {
    crate::libc::unistd::_exit(status);
}

#[no_mangle]
pub extern "C" fn quick_exit(status: i32) -> ! {
    crate::libc::unistd::_exit(status);
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    unsafe { crate::libc::signal::raise(6) };
    crate::arch::x86_64::boot::cpu_ops::halt_loop()
}

#[no_mangle]
pub extern "C" fn atexit(func: AtexitFn) -> i32 {
    atexit_register(func)
}

pub fn atexit_register(func: AtexitFn) -> i32 {
    let idx = ATEXIT_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    if idx >= MAX_ATEXIT { return -1; }
    ATEXIT_FUNCS.lock()[idx] = Some(func);
    0
}

fn run_atexit_handlers() {
    let count = ATEXIT_COUNT.load(core::sync::atomic::Ordering::SeqCst);
    let funcs = *ATEXIT_FUNCS.lock();
    for i in (0..count).rev() {
        if let Some(f) = funcs[i] { f(); }
    }
}

#[no_mangle]
pub extern "C" fn at_quick_exit(_func: AtexitFn) -> i32 {
    0
}
