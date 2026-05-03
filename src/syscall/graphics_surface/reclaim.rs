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

use crate::memory::frame_alloc::deallocate_frame;
use crate::memory::paging::unmap_page;
use crate::memory::VirtAddr;

use super::registry::drain_owned_by;

const PAGE_SIZE: u64 = 4096;

pub fn release_for(owner_pid: u32) {
    for surface in drain_owned_by(owner_pid) {
        if let Some(base) = surface.mapped_va {
            for i in 0..surface.frames.len() as u64 {
                let _ = unmap_page(VirtAddr::new(base + i * PAGE_SIZE));
            }
        }
        for frame in surface.frames {
            let _ = deallocate_frame(frame);
        }
    }
}
