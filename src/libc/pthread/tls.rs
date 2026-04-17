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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub type PthreadKeyT = u32;
pub type Destructor = extern "C" fn(*mut u8);

const PTHREAD_KEYS_MAX: usize = 128;

static NEXT_KEY: AtomicU32 = AtomicU32::new(0);
static KEY_DESTRUCTORS: [AtomicUsize; PTHREAD_KEYS_MAX] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; PTHREAD_KEYS_MAX]
};

#[thread_local]
static mut TLS_VALUES: [*mut u8; PTHREAD_KEYS_MAX] = [ptr::null_mut(); PTHREAD_KEYS_MAX];

static STACK_CANARY: AtomicU64 = AtomicU64::new(0);

pub fn set_stack_canary(canary: u64) {
    STACK_CANARY.store(canary, Ordering::SeqCst);
}

pub fn get_stack_canary() -> u64 {
    STACK_CANARY.load(Ordering::SeqCst)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_key_create(key: *mut PthreadKeyT, destructor: Option<Destructor>) -> i32 {
    if key.is_null() { return 22; }
    loop {
        let current = NEXT_KEY.load(Ordering::SeqCst);
        if current as usize >= PTHREAD_KEYS_MAX { return 11; }
        if NEXT_KEY.compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            if let Some(d) = destructor {
                KEY_DESTRUCTORS[current as usize].store(d as usize, Ordering::SeqCst);
            }
            ptr::write(key, current);
            return 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_key_delete(key: PthreadKeyT) -> i32 {
    if key as usize >= PTHREAD_KEYS_MAX { return 22; }
    KEY_DESTRUCTORS[key as usize].store(0, Ordering::SeqCst);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getspecific(key: PthreadKeyT) -> *mut u8 {
    if key as usize >= PTHREAD_KEYS_MAX { return ptr::null_mut(); }
    TLS_VALUES[key as usize]
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setspecific(key: PthreadKeyT, value: *const u8) -> i32 {
    if key as usize >= PTHREAD_KEYS_MAX { return 22; }
    TLS_VALUES[key as usize] = value as *mut u8;
    0
}

pub unsafe fn run_tls_destructors() {
    for _ in 0..4 {
        let mut any = false;
        for k in 0..PTHREAD_KEYS_MAX {
            let val = TLS_VALUES[k];
            if !val.is_null() {
                TLS_VALUES[k] = ptr::null_mut();
                let dtor = KEY_DESTRUCTORS[k].load(Ordering::SeqCst);
                if dtor != 0 {
                    let f: Destructor = core::mem::transmute(dtor);
                    f(val);
                    any = true;
                }
            }
        }
        if !any { break; }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_once(once_control: *mut i32, init_routine: extern "C" fn()) -> i32 {
    if once_control.is_null() { return 22; }
    if core::sync::atomic::AtomicI32::from_ptr(once_control).compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        init_routine();
    }
    0
}
