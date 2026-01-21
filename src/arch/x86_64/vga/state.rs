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

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use crate::arch::x86_64::vga::console::Console;
use crate::arch::x86_64::vga::constants::MAX_CONSOLES;

pub(crate) static mut CONSOLES: [Console; MAX_CONSOLES] = [
    Console::new(),
    Console::new(),
    Console::new(),
    Console::new(),
];

pub(crate) static ACTIVE_CONSOLE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static VGA_LOCK: AtomicBool = AtomicBool::new(false);
pub(crate) static PANIC_MODE: AtomicBool = AtomicBool::new(false);
pub(crate) static CHARS_WRITTEN: AtomicU64 = AtomicU64::new(0);
pub(crate) static LINES_SCROLLED: AtomicU64 = AtomicU64::new(0);
pub(crate) static CONSOLE_SWITCHES: AtomicU64 = AtomicU64::new(0);
