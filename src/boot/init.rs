// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[inline]
pub fn init_vga_output() {
    vga::show_boot_splash();
}

#[inline]
pub fn init_early() {}

#[inline]
pub fn init_panic_handler() {}

#[inline]
pub fn serial_print_wrapper(args: core::fmt::Arguments) {
    super::stage1::serial_print(args);
}
