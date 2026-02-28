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

use core::fmt::{self, Write};
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use super::super::constants::MAX_CONSOLES;
use super::super::cursor::update_cursor;
use super::super::error::VgaError;
use super::super::state::{ACTIVE_CONSOLE, CONSOLE_SWITCHES, CONSOLES};
use super::lock::{acquire_lock, release_lock};
use super::write::write_str_to_console;

pub fn active_console() -> usize {
    ACTIVE_CONSOLE.load(Ordering::Acquire)
}

pub fn switch_console(index: usize) -> Result<(), VgaError> {
    if index >= MAX_CONSOLES {
        return Err(VgaError::InvalidConsole);
    }

    if !acquire_lock() {
        return Err(VgaError::LockContention);
    }

    ACTIVE_CONSOLE.store(index, Ordering::Release);
    CONSOLE_SWITCHES.fetch_add(1, Ordering::Relaxed);

    // SAFETY: Index bounds checked, lock held
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        (*consoles)[index].flush_to_vga();
        update_cursor((*consoles)[index].row, (*consoles)[index].col);
    }

    release_lock();
    Ok(())
}

pub struct VgaWriter {
    console: usize,
}

impl VgaWriter {
    pub fn new() -> Self {
        Self {
            console: ACTIVE_CONSOLE.load(Ordering::Acquire),
        }
    }

    pub fn for_console(console: usize) -> Self {
        Self { console }
    }
}

impl Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let _ = write_str_to_console(self.console, s);
        Ok(())
    }
}

impl Default for VgaWriter {
    fn default() -> Self {
        Self::new()
    }
}
