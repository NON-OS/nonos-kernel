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

use super::vga;
use core::fmt::Write;

#[inline]
pub fn init_vga_output() {
    vga::show_boot_splash();
}

#[inline]
pub fn init_early() {
    crate::process::init_process_management();
}

#[inline]
pub fn init_panic_handler() {}

// Backs the `serial_print!` / `serial_println!` macros. The legacy
// `boot::stage1::serial_print` is gated off; the trusted-path serial
// sink is `crate::sys::serial::print`, the same byte-stream the panic
// path already uses.
struct SerialWriter;
impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        crate::sys::serial::print(s.as_bytes());
        Ok(())
    }
}

#[inline]
pub fn serial_print_wrapper(args: core::fmt::Arguments) {
    let _ = SerialWriter.write_fmt(args);
}
