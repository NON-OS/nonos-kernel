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

use super::super::{
    buddy_alloc as allocator,
    hardening::{verify_kernel_data_integrity, verify_kernel_page_tables},
    heap, kaslr, layout, phys, safety,
};
use x86_64::PhysAddr;

pub fn init_all_memory_subsystems() -> Result<(), &'static str> {
    layout::validate_layout().map_err(|_| "Layout validation failed")?;
    phys::init(PhysAddr::new(0x100000), PhysAddr::new(0x40000000))
        .map_err(|_| "Physical memory init failed")?;
    super::super::frame_alloc::init().map_err(|_| "Frame allocator init failed")?;
    heap::init().map_err(|_| "Heap init failed")?;
    allocator::init().map_err(|_| "Allocator init failed")?;
    safety::init().map_err(|_| "Safety module init failed")?;
    super::super::hardening::init_module_memory_protection();
    kaslr::validate().map_err(|_| "KASLR validation failed")?;
    Ok(())
}

pub fn verify_all_memory_integrity() -> Result<(), &'static str> {
    if !heap::verify_heap_integrity() {
        return Err("Heap integrity check failed");
    }
    if !safety::verify_stack_integrity() {
        return Err("Stack integrity check failed");
    }
    if !kaslr::verify_slide_integrity() {
        return Err("KASLR integrity check failed");
    }
    if !verify_kernel_data_integrity() {
        return Err("Kernel data integrity check failed");
    }
    if !verify_kernel_page_tables() {
        return Err("Page table integrity check failed");
    }
    Ok(())
}
