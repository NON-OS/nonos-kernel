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

#[cfg(feature = "kernel")]
use core::alloc::Layout;
use core::ptr;

extern "C" {
    #[cfg(not(feature = "kernel"))]
    fn sbrk(increment: isize) -> *mut u8;
}

const MIN_ALIGN: usize = 16;

fn align_up(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    let Some(with_header) = size.checked_add(16) else {
        return ptr::null_mut();
    };
    let total = align_up(with_header, MIN_ALIGN);
    if total < size {
        return ptr::null_mut();
    }
    #[cfg(feature = "kernel")]
    let ptr = {
        let Ok(layout) = Layout::from_size_align(total, MIN_ALIGN) else {
            return ptr::null_mut();
        };
        alloc::alloc::alloc(layout)
    };
    #[cfg(not(feature = "kernel"))]
    let ptr = sbrk(total as isize);
    if ptr.is_null() {
        return ptr::null_mut();
    }
    ptr::write(ptr as *mut usize, total);
    ptr::write((ptr as *mut usize).add(1), size);
    ptr.add(16)
}

#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let total = nmemb.checked_mul(size).unwrap_or(0);
    if total == 0 {
        return ptr::null_mut();
    }
    let p = malloc(total);
    if !p.is_null() {
        crate::libc::string::memset::memset(p, 0, total);
    }
    p
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return malloc(new_size);
    }
    if new_size == 0 {
        super::free::free(ptr);
        return ptr::null_mut();
    }
    let header = ptr.sub(16);
    let old_size = ptr::read((header as *const usize).add(1));
    if new_size <= old_size {
        return ptr;
    }
    let new_ptr = malloc(new_size);
    if new_ptr.is_null() {
        return ptr::null_mut();
    }
    crate::libc::string::memcpy::memcpy(new_ptr, ptr, old_size);
    super::free::free(ptr);
    new_ptr
}

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut u8 {
    if alignment == 0 || (alignment & (alignment - 1)) != 0 {
        return ptr::null_mut();
    }
    if size == 0 {
        return ptr::null_mut();
    }
    let actual_align = alignment.max(MIN_ALIGN);
    let Some(with_align) = size.checked_add(actual_align) else {
        return ptr::null_mut();
    };
    let Some(with_header) = with_align.checked_add(16) else {
        return ptr::null_mut();
    };
    let total = align_up(with_header, actual_align);
    if total < size {
        return ptr::null_mut();
    }
    #[cfg(feature = "kernel")]
    let raw = {
        let Ok(layout) = Layout::from_size_align(total, actual_align) else {
            return ptr::null_mut();
        };
        alloc::alloc::alloc(layout)
    };
    #[cfg(not(feature = "kernel"))]
    let raw = sbrk(total as isize);
    if raw.is_null() {
        return ptr::null_mut();
    }
    let aligned = align_up(raw as usize + 16, actual_align) as *mut u8;
    let header = aligned.sub(16);
    ptr::write(header as *mut usize, total);
    ptr::write((header as *mut usize).add(1), size);
    aligned
}

#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut u8,
    alignment: usize,
    size: usize,
) -> i32 {
    if alignment < core::mem::size_of::<*mut u8>() || (alignment & (alignment - 1)) != 0 {
        return 22;
    }
    let p = aligned_alloc(alignment, size);
    if p.is_null() {
        return 12;
    }
    ptr::write(memptr, p);
    0
}
