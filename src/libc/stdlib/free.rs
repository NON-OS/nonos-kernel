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
use core::alloc::Layout;

const MIN_ALIGN: usize = 16;

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() { return; }
    let header = ptr.sub(16);
    let total_size = ptr::read(header as *const usize);
    #[cfg(feature = "kernel")]
    {
        let layout = Layout::from_size_align_unchecked(total_size, MIN_ALIGN);
        alloc::alloc::dealloc(header, layout);
    }
    #[cfg(not(feature = "kernel"))]
    {
        let _ = total_size;
    }
}

#[no_mangle]
pub unsafe extern "C" fn cfree(ptr: *mut u8) {
    free(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut u8) -> usize {
    if ptr.is_null() { return 0; }
    let header = ptr.sub(16);
    ptr::read((header as *const usize).add(1))
}
