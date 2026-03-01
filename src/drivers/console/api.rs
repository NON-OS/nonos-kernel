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

use core::fmt;
use core::sync::atomic::Ordering;
use spin::Mutex;

use super::types::{Color, ConsoleStats, ConsoleStatsSnapshot};
use super::writer::Console;

static CONSOLE: Mutex<Console> = Mutex::new(Console::new());

static CONSOLE_STATS: ConsoleStats = ConsoleStats::new();

pub fn init_console() {
    CONSOLE.lock().init();
}

pub fn clear() {
    CONSOLE.lock().clear();
}

pub fn set_color(fg: Color, bg: Color) {
    CONSOLE.lock().set_color(fg, bg);
}

pub fn print(s: &str) {
    CONSOLE.lock().write_str(s);
}

pub fn println(s: &str) {
    let mut console = CONSOLE.lock();
    console.write_str(s);
    console.put_byte(b'\n');
    console.flush_cursor();
}

pub fn printf(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut w = ConsoleWriter;
    let _ = w.write_fmt(args);
}

pub fn write_message(msg: &str) {
    CONSOLE_STATS.inc_messages();
    CONSOLE_STATS.add_bytes(msg.len() as u64);
    CONSOLE.lock().write_str(msg);
}

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

pub fn get_stats_snapshot() -> ConsoleStatsSnapshot {
    let mut snapshot = CONSOLE_STATS.snapshot();
    snapshot.uptime_ticks = crate::time::current_ticks();
    snapshot
}

struct ConsoleWriter;

impl fmt::Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        print(s);
        Ok(())
    }
}
