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

// Writes `argb` across the whole backing buffer. `stride_bytes`
// counts bytes (not pixels) so it matches the surface descriptor
// the kernel returned through the registry.
pub fn fill_argb(base_va: u64, stride_bytes: u32, width: u32, height: u32, argb: u32) {
    if width == 0 || height == 0 {
        return;
    }
    let stride = stride_bytes as usize;
    for row in 0..height as usize {
        let row_base = base_va as usize + row * stride;
        for col in 0..width as usize {
            let cell = (row_base + col * 4) as *mut u32;
            // SAFETY: caller holds the mapped surface for the
            // (width, height) span; the loop never reads past it.
            unsafe { core::ptr::write_volatile(cell, argb) };
        }
    }
}
