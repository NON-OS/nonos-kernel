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

//! Text-mode UI used as fallback and for early boot diagnostics.

#![cfg(feature = "ui")]

use alloc::string::String;
use spin::Mutex;

static TUI: Mutex<Option<Terminal>> = Mutex::new(None);

pub struct Terminal {
    pub cols: usize,
    pub rows: usize,
    pub buffer: alloc::vec::Vec<alloc::string::String>,
}

impl Terminal {
    pub fn new(cols: usize, rows: usize) -> Self {
        let mut buf = alloc::vec::Vec::with_capacity(rows);
        for _ in 0..rows {
            buf.push(String::new());
        }
        Terminal { cols, rows, buffer: buf }
    }

    /// Write a string; wraps and scrolls deterministically.
    pub fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch == '\n' {
                self.scroll_up();
                continue;
            }
            let needs_scroll = if let Some(last) = self.buffer.last() {
                last.len() >= self.cols
            } else {
                false
            };

            if needs_scroll {
                self.scroll_up();
            }

            if let Some(last) = self.buffer.last_mut() {
                last.push(ch);
            }
        }
        // Also emit to VGA device for early visibility.
        crate::arch::x86_64::vga::print(s);
    }

    fn scroll_up(&mut self) {
        if !self.buffer.is_empty() {
            self.buffer.remove(0);
        }
        self.buffer.push(String::new());
    }
}

pub fn init_tui() {
    let mut g = TUI.lock();
    if g.is_none() {
        *g = Some(Terminal::new(80, 25));
        crate::log_info!("ui: tui initialized");
    }
}

pub fn write_line(s: &str) {
    let mut g = TUI.lock();
    if let Some(ref mut t) = *g {
        t.write_str(s);
    } else {
        crate::arch::x86_64::vga::print(s);
    }
}
