// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

mod constants;
mod types;
mod vga;
mod ansi;
mod writer;

#[cfg(test)]
mod tests;

use core::fmt;
use core::sync::atomic::Ordering;
use spin::Mutex;
pub use constants::*;
pub use types::{Color, VgaCell, LogLevel, ConsoleStats, ConsoleStatsSnapshot};
pub use ansi::{AnsiParser, AnsiAction, ParserState, apply_sgr};
use writer::Console;

/// Global console instance protected by mutex.
static CONSOLE: Mutex<Console> = Mutex::new(Console::new());

/// Global console statistics.
static CONSOLE_STATS: ConsoleStats = ConsoleStats::new();

// Public API
pub fn init_console() {
    CONSOLE.lock().clear();
}

/// Clears the entire screen.
pub fn clear() {
    CONSOLE.lock().clear();
}

/// Sets the current foreground and background colors.
pub fn set_color(fg: Color, bg: Color) {
    CONSOLE.lock().set_color(fg, bg);
}

/// Prints a string to the console.
pub fn print(s: &str) {
    CONSOLE.lock().write_str(s);
}

/// Prints a string followed by a newline.
pub fn println(s: &str) {
    let mut console = CONSOLE.lock();
    console.write_str(s);
    console.put_byte(b'\n');
    console.flush_cursor();
}

/// Prints formatted text to the console.
pub fn printf(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut w = ConsoleWriter;
    let _ = w.write_fmt(args);
}

/// Writes a message to console with statistics tracking.
pub fn write_message(msg: &str) {
    CONSOLE_STATS.inc_messages();
    CONSOLE_STATS.add_bytes(msg.len() as u64);
    CONSOLE.lock().write_str(msg);
}

/// Returns a snapshot of console statistics.
pub fn get_console_stats() -> ConsoleStats {
    ConsoleStats {
        messages_written: core::sync::atomic::AtomicU64::new(
            CONSOLE_STATS.messages_written.load(Ordering::Relaxed)
        ),
        bytes_written: core::sync::atomic::AtomicU64::new(
            CONSOLE_STATS.bytes_written.load(Ordering::Relaxed)
        ),
        errors: core::sync::atomic::AtomicU64::new(
            CONSOLE_STATS.errors.load(Ordering::Relaxed)
        ),
        uptime_ticks: core::sync::atomic::AtomicU64::new(
            crate::time::current_ticks()
        ),
    }
}

/// Returns a non-atomic snapshot of console statistics.
pub fn get_stats_snapshot() -> ConsoleStatsSnapshot {
    let mut snapshot = CONSOLE_STATS.snapshot();
    snapshot.uptime_ticks = crate::time::current_ticks();
    snapshot
}

/// Writer adapter for `core::fmt::Write`.
struct ConsoleWriter;

impl fmt::Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        print(s);
        Ok(())
    }
}

// =============================================================================
// Macros
// =============================================================================

/// Prints formatted text to the console.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::drivers::console::printf(format_args!($($arg)*)));
}

/// Prints formatted text followed by a newline.
#[macro_export]
macro_rules! kprintln {
    () => ($crate::drivers::console::println(""));
    ($fmt:expr) => ($crate::drivers::console::println($fmt));
    ($fmt:expr, $($arg:tt)*) => ($crate::drivers::console::printf(format_args!(concat!($fmt, "\n"), $($arg)*)));
}
