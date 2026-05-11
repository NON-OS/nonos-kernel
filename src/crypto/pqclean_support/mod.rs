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

//! Rust glue for the PQClean C archives the kernel build.rs links in.
//!
//! `libc_glue.c` provides the `malloc`/`free`/`exit` symbols PQClean
//! expects from a hosted libc; each one tail-calls into a Rust function
//! exported from this module. `randombytes.c` does the same for the
//! `randombytes` entropy hook. Both C archives are compiled
//! unconditionally by `build.rs`, so these definitions must live outside
//! every PQClean-algorithm feature gate — otherwise a kernel built
//! without (for example) any `mlkem*` feature still pulls libc_glue.o
//! in via the ML-DSA archive and fails to link.
//!
//! The functions take the simplest correct shape that still routes
//! through the kernel's global allocator and serial sink. PQClean does
//! not care about how `malloc` rounds up its request, only that `free`
//! can recover the original size; we stash a `usize` length prefix at
//! the start of every block.

extern crate alloc;

#[no_mangle]
pub extern "C" fn nonos_randombytes(buf: *mut u8, n: usize) {
    if buf.is_null() || n == 0 {
        return;
    }
    unsafe {
        let slice = core::slice::from_raw_parts_mut(buf, n);
        crate::crypto::rng::fill_random_bytes(slice);
    }
}

#[no_mangle]
pub extern "C" fn nonos_malloc(size: usize) -> *mut u8 {
    use alloc::alloc::{alloc, Layout};
    if size == 0 {
        return core::ptr::null_mut();
    }
    let total = size + core::mem::size_of::<usize>();
    // align = 8 is mandatory, not advisory — the usize length prefix
    // we stash at offset 0 needs a usize-aligned address on x86_64.
    let layout = match Layout::from_size_align(total, 8) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        // Cast safe: `Layout::from_size_align(total, 8)` above pins
        // the returned address to a usize-sized boundary.
        #[allow(clippy::cast_ptr_alignment)]
        let header = raw.cast::<usize>();
        header.write(size);
        raw.add(core::mem::size_of::<usize>())
    }
}

#[no_mangle]
pub extern "C" fn nonos_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    use alloc::alloc::{dealloc, Layout};
    let header_size = core::mem::size_of::<usize>();
    let raw = unsafe { ptr.sub(header_size) };
    // Cast safe: paired with `nonos_malloc`, which only returns
    // pointers laid out by an align = 8 Layout.
    #[allow(clippy::cast_ptr_alignment)]
    let size = unsafe { raw.cast::<usize>().read() };
    let total = size + header_size;
    if let Ok(layout) = Layout::from_size_align(total, 8) {
        unsafe {
            dealloc(raw, layout);
        }
    }
}

#[no_mangle]
pub extern "C" fn nonos_panic() -> ! {
    crate::sys::serial::println(b"[FATAL] PQClean fatal error");
    crate::arch::halt_loop()
}
