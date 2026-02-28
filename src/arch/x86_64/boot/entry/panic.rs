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

use super::super::cpu_ops::{cli, hlt};
use super::super::error::BootError;
use super::super::state::set_error;
use crate::arch::x86_64::{serial, vga};

pub unsafe fn boot_panic(error: BootError) -> ! {
    set_error(error);

    if serial::is_initialized() {
        serial::write_str("\n!!! BOOT PANIC: ");
        serial::write_str(error.as_str());
        serial::write_str("\n");
    }

    if vga::is_initialized() {
        vga::enter_panic_mode();
        vga::set_color(vga::Color::LightRed, vga::Color::Black);
        vga::write_str("\n\nBOOT PANIC: ");
        vga::write_str(error.as_str());
        vga::write_str("\n");
    }

    loop {
        cli();
        hlt();
    }
}
