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

use core::sync::atomic::Ordering;
use super::super::state::{ACTIVE_CONSOLE, CHARS_WRITTEN, CONSOLE_SWITCHES, INITIALIZED, LINES_SCROLLED};

#[derive(Debug, Clone, Copy, Default)]
pub struct VgaStats {
    pub chars_written: u64,
    pub lines_scrolled: u64,
    pub console_switches: u64,
    pub active_console: usize,
    pub initialized: bool,
}

pub fn get_stats() -> VgaStats {
    VgaStats {
        chars_written: CHARS_WRITTEN.load(Ordering::Relaxed),
        lines_scrolled: LINES_SCROLLED.load(Ordering::Relaxed),
        console_switches: CONSOLE_SWITCHES.load(Ordering::Relaxed),
        active_console: ACTIVE_CONSOLE.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}
