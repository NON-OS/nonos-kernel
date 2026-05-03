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

use super::super::constants::*;
use super::super::error::FrameResult;
use super::super::types::FrameAllocator;
use crate::memory::addr::PhysAddr;
use spin::Mutex;

static GLOBAL_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());

pub fn init() -> FrameResult<()> {
    let mut allocator = GLOBAL_ALLOCATOR.lock();
    if allocator.is_initialized() {
        return Ok(());
    }
    allocator.init()?;
    if allocator.usable.is_empty() {
        let start = PhysAddr::new(DEFAULT_REGION_START);
        let end = PhysAddr::new(DEFAULT_REGION_END);
        allocator.add_region(start, end)?;
    }
    Ok(())
}

pub fn get_allocator() -> &'static Mutex<FrameAllocator> {
    &GLOBAL_ALLOCATOR
}

pub fn is_initialized() -> bool {
    GLOBAL_ALLOCATOR.lock().is_initialized()
}
