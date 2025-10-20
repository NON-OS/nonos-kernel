//! Text-mode UI used as fallback and for early boot diagnostics.

#![cfg(feature = "ui")]

use alloc::string::String;
use core::fmt::Write;
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
            if let Some(last) = self.buffer.last_mut() {
                if last.len() >= self.cols {
                    self.scroll_up();
                }
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
