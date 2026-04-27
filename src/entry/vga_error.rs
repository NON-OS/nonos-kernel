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

use core::fmt::Write;

struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> core::fmt::Write for SliceWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.pos);
        let to_copy = core::cmp::min(avail, bytes.len());
        if to_copy == 0 {
            return Err(core::fmt::Error);
        }
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}

pub fn early_vga_error(args: core::fmt::Arguments<'_>) {
    let mut buf = [0u8; 256];
    let mut writer = SliceWriter { buf: &mut buf, pos: 0 };
    let _ = writer.write_fmt(args);
    let len = writer.pos;
    unsafe {
        let vga_base = 0xb8000 as *mut u16;
        let attr: u16 = 0x4F00;
        for i in 0..len {
            core::ptr::write_volatile(vga_base.add(i), (buf[i] as u16) | attr);
        }
    }
}

pub fn halt_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
