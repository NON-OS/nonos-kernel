// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::arch::asm;

pub fn vga_fallback() -> ! {
    const VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;
    unsafe {
        for i in 0..(80 * 25) {
            *VGA_BUFFER.add(i * 2) = b' ';
            *VGA_BUFFER.add(i * 2 + 1) = 0x1F;
        }
        let msg = b"NONOS v1.0.0 - No framebuffer available";
        for (i, &ch) in msg.iter().enumerate() {
            *VGA_BUFFER.add(i * 2) = ch;
        }
    }
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}
