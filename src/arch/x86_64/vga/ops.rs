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

use core::fmt::{self, Write};
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use crate::arch::x86_64::vga::constants::*;
use crate::arch::x86_64::vga::cursor::{enable_cursor, update_cursor};
use crate::arch::x86_64::vga::error::VgaError;
use crate::arch::x86_64::vga::state::*;

fn acquire_lock() -> bool {
    if PANIC_MODE.load(Ordering::Relaxed) {
        return true;
    }

    let mut attempts = 0;
    while VGA_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        attempts += 1;
        if attempts > 1000 {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

fn release_lock() {
    if !PANIC_MODE.load(Ordering::Relaxed) {
        VGA_LOCK.store(false, Ordering::Release);
    }
}

pub fn init() -> Result<(), VgaError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(VgaError::AlreadyInitialized);
    }

    // SAFETY: Single-threaded initialization, using addr_of_mut! to avoid creating references to mutable static
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        for i in 0..MAX_CONSOLES {
            (*consoles)[i].clear();
        }
    }

    enable_cursor(14, 15);

    // SAFETY: Single-threaded initialization
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        (*consoles)[0].flush_to_vga();
    }

    update_cursor(0, 0);

    Ok(())
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn enter_panic_mode() {
    PANIC_MODE.store(true, Ordering::Release);
}

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

pub fn write_byte(byte: u8) {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    // SAFETY: Index from atomic, lock held
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        (*consoles)[index].write_byte(byte);
        (*consoles)[index].flush_to_vga();
        update_cursor((*consoles)[index].row, (*consoles)[index].col);
    }
    CHARS_WRITTEN.fetch_add(1, Ordering::Relaxed);

    release_lock();
}

pub fn write_str(s: &str) {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    // SAFETY: Index from atomic, lock held
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        for byte in s.bytes() {
            (*consoles)[index].write_byte(byte);
        }
        (*consoles)[index].flush_to_vga();
        update_cursor((*consoles)[index].row, (*consoles)[index].col);
    }
    CHARS_WRITTEN.fetch_add(s.len() as u64, Ordering::Relaxed);

    release_lock();
}

pub fn write_str_to_console(index: usize, s: &str) -> Result<(), VgaError> {
    if index >= MAX_CONSOLES {
        return Err(VgaError::InvalidConsole);
    }

    if !acquire_lock() {
        return Err(VgaError::LockContention);
    }

    // SAFETY: Index bounds checked, lock held
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        for byte in s.bytes() {
            (*consoles)[index].write_byte(byte);
        }

        if index == ACTIVE_CONSOLE.load(Ordering::Relaxed) {
            (*consoles)[index].flush_to_vga();
            update_cursor((*consoles)[index].row, (*consoles)[index].col);
        }
    }

    release_lock();
    Ok(())
}

pub fn clear() {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    // SAFETY: Index from atomic, lock held
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        (*consoles)[index].clear();
        (*consoles)[index].flush_to_vga();
        update_cursor(0, 0);
    }

    release_lock();
}

pub fn set_color(fg: Color, bg: Color) {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    // SAFETY: Index from atomic, lock held
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        (*consoles)[index].set_color(fg, bg);
    }

    release_lock();
}

pub fn print_critical(s: &str) {
    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    // SAFETY: Panic-safe path, bypasses locking
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        for byte in s.bytes() {
            (*consoles)[index].write_byte(byte);
        }
        (*consoles)[index].flush_to_vga();
    }
}

pub fn print_hex(value: u64) {
    const HEX_CHARS: &[u8] = b"0123456789ABCDEF";
    let mut buffer = [b'0'; 18];
    buffer[0] = b'0';
    buffer[1] = b'x';

    for i in 0..16 {
        let nibble = ((value >> (60 - i * 4)) & 0xF) as usize;
        buffer[2 + i] = HEX_CHARS[nibble];
    }

    if let Ok(s) = core::str::from_utf8(&buffer) {
        write_str(s);
    }
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
