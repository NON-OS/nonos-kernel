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

pub fn allocate_secure_memory(size: usize) -> *mut u8 {
    crate::memory::allocator::allocate_aligned(size, 8).ok().map(|va| va.as_mut_ptr::<u8>()).unwrap_or(core::ptr::null_mut())
}

pub fn deallocate_secure_memory(ptr: *mut u8, _size: usize) {
    crate::memory::allocator::free_pages(x86_64::VirtAddr::from_ptr(ptr), 1).ok();
}
