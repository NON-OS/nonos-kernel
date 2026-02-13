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

use super::constants::{
    COLOR_BACKGROUND, COLOR_ERROR, COLOR_SUCCESS, COLOR_TEXT_DIM, COLOR_WARNING,
};
use super::font::draw_string;
use super::gop::fill_rect;
use core::sync::atomic::{AtomicUsize, Ordering};

const MAX_LOG_LINES: usize = 30;
const LOG_LINE_LEN: usize = 58;
const LOG_X: u32 = 12;
const LOG_Y_START: u32 = 218;
const LINE_HEIGHT: u32 = 13;

#[derive(Clone, Copy)]
pub enum LogLevel {
    Info,
    Ok,
    Warn,
    Error,
}

#[derive(Clone, Copy)]
struct LogEntry {
    text: [u8; LOG_LINE_LEN],
    len: usize,
    level: LogLevel,
}

impl LogEntry {
    const fn empty() -> Self {
        Self {
            text: [0u8; LOG_LINE_LEN],
            len: 0,
            level: LogLevel::Info,
        }
    }
}

static mut LOG_BUFFER: [LogEntry; MAX_LOG_LINES] = [LogEntry::empty(); MAX_LOG_LINES];
static LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Small delay for log visibility
fn log_delay() {
    for _ in 0..800_000 {
        core::hint::spin_loop();
    }
}

pub fn log(level: LogLevel, msg: &[u8]) {
    let count = LOG_COUNT.load(Ordering::Relaxed);
    let idx = count % MAX_LOG_LINES;

    // ## SAFETY: Single-threaded bootloader context
    unsafe {
        let entry = &mut LOG_BUFFER[idx];
        entry.level = level;
        entry.text = [0u8; LOG_LINE_LEN];
        entry.len = msg.len().min(LOG_LINE_LEN);
        entry.text[..entry.len].copy_from_slice(&msg[..entry.len]);
    }

    LOG_COUNT.store(count + 1, Ordering::Release);
    // Always do full redraw to prevent overlap
    redraw_visible(count + 1);
    log_delay();
}

fn redraw_visible(total: usize) {
    // Clear entire log area
    let log_height = (MAX_LOG_LINES as u32) * LINE_HEIGHT + 4;
    fill_rect(
        LOG_X - 2,
        LOG_Y_START - 2,
        480,
        log_height,
        COLOR_BACKGROUND,
    );

    if total == 0 {
        return;
    }

    let visible_count = total.min(MAX_LOG_LINES);
    let start_entry = if total > MAX_LOG_LINES {
        total - MAX_LOG_LINES
    } else {
        0
    };

    for line in 0..visible_count {
        let entry_idx = (start_entry + line) % MAX_LOG_LINES;
        let y = LOG_Y_START + (line as u32) * LINE_HEIGHT;

        unsafe {
            let entry = &LOG_BUFFER[entry_idx];
            if entry.len == 0 {
                continue;
            }

            let (prefix, color) = match entry.level {
                LogLevel::Info => (b"    " as &[u8], COLOR_TEXT_DIM),
                LogLevel::Ok => (b"[+] " as &[u8], COLOR_SUCCESS),
                LogLevel::Warn => (b"[!] " as &[u8], COLOR_WARNING),
                LogLevel::Error => (b"[X] " as &[u8], COLOR_ERROR),
            };

            draw_string(LOG_X, y, prefix, color);
            draw_string(LOG_X + 32, y, &entry.text[..entry.len], color);
        }
    }
}

pub fn log_info(msg: &[u8]) {
    log(LogLevel::Info, msg);
}

pub fn log_ok(msg: &[u8]) {
    log(LogLevel::Ok, msg);
}

pub fn log_warn(msg: &[u8]) {
    log(LogLevel::Warn, msg);
}

pub fn log_error(msg: &[u8]) {
    log(LogLevel::Error, msg);
}

pub fn log_hex(prefix: &[u8], value: u64) {
    let mut buf = [0u8; 58];
    let mut pos = 0;

    for &b in prefix {
        if pos < buf.len() {
            buf[pos] = b;
            pos += 1;
        }
    }

    if pos + 2 < buf.len() {
        buf[pos] = b'0';
        buf[pos + 1] = b'x';
        pos += 2;
    }

    let hex_chars = b"0123456789abcdef";
    for i in (0..16).rev() {
        if pos < buf.len() {
            let nibble = ((value >> (i * 4)) & 0xF) as usize;
            buf[pos] = hex_chars[nibble];
            pos += 1;
        }
    }

    log(LogLevel::Ok, &buf[..pos]);
}

pub fn log_hash(prefix: &[u8], hash: &[u8]) {
    let mut buf = [0u8; 58];
    let mut pos = 0;

    for &b in prefix {
        if pos < buf.len() {
            buf[pos] = b;
            pos += 1;
        }
    }

    let hex_chars = b"0123456789abcdef";
    // Show first 16 bytes (32 hex chars)
    for &byte in hash.iter().take(16) {
        if pos + 2 <= buf.len() {
            buf[pos] = hex_chars[(byte >> 4) as usize];
            buf[pos + 1] = hex_chars[(byte & 0xF) as usize];
            pos += 2;
        }
    }

    log(LogLevel::Ok, &buf[..pos]);
    // Second line for remaining bytes
    if hash.len() > 16 {
        let mut buf2 = [0u8; 58];
        buf2[0..6].copy_from_slice(b"      ");
        let mut pos2 = 6;

        for &byte in hash.iter().skip(16) {
            if pos2 + 2 <= buf2.len() {
                buf2[pos2] = hex_chars[(byte >> 4) as usize];
                buf2[pos2 + 1] = hex_chars[(byte & 0xF) as usize];
                pos2 += 2;
            }
        }
        log(LogLevel::Info, &buf2[..pos2]);
    }
}

pub fn log_hash_full(label: &[u8], hash: &[u8]) {
    log(LogLevel::Ok, label);

    let hex_chars = b"0123456789abcdef";
    let mut buf = [0u8; 58];
    buf[0..4].copy_from_slice(b"  0x");
    let mut pos = 4;

    for &byte in hash {
        if pos + 2 <= buf.len() {
            buf[pos] = hex_chars[(byte >> 4) as usize];
            buf[pos + 1] = hex_chars[(byte & 0xF) as usize];
            pos += 2;
        }
    }
    log(LogLevel::Info, &buf[..pos]);
}

pub fn log_mem(start: u64, end: u64, kind: &[u8]) {
    let mut buf = [0u8; 58];
    let hex = b"0123456789abcdef";
    // Format: 0xSTART-0xEND TYPE
    let mut pos = 0;
    buf[pos..pos + 2].copy_from_slice(b"0x");
    pos += 2;
    // Start address (12 hex digits for readability)
    for i in (0..12).rev() {
        buf[pos] = hex[((start >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }

    buf[pos] = b'-';
    pos += 1;

    buf[pos..pos + 2].copy_from_slice(b"0x");
    pos += 2;
    // End address
    for i in (0..12).rev() {
        buf[pos] = hex[((end >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }

    buf[pos] = b' ';
    pos += 1;

    let klen = kind.len().min(buf.len() - pos);
    buf[pos..pos + klen].copy_from_slice(&kind[..klen]);
    pos += klen;

    log(LogLevel::Info, &buf[..pos]);
}

pub fn log_size(prefix: &[u8], size: usize) {
    let mut buf = [0u8; 58];
    let mut pos = 0;

    for &b in prefix {
        if pos < buf.len() {
            buf[pos] = b;
            pos += 1;
        }
    }

    let mut num_buf = [0u8; 12];
    let mut num_pos = 0;
    let mut n = size;
    if n == 0 {
        num_buf[0] = b'0';
        num_pos = 1;
    } else {
        while n > 0 && num_pos < 12 {
            num_buf[num_pos] = b'0' + (n % 10) as u8;
            n /= 10;
            num_pos += 1;
        }
    }

    for i in (0..num_pos).rev() {
        if pos < buf.len() {
            buf[pos] = num_buf[i];
            pos += 1;
        }
    }

    if pos + 6 <= buf.len() {
        buf[pos..pos + 6].copy_from_slice(b" bytes");
        pos += 6;
    }

    log(LogLevel::Ok, &buf[..pos]);
}

pub fn log_u32(prefix: &[u8], value: u32) {
    let mut buf = [0u8; 58];
    let mut pos = 0;

    for &b in prefix {
        if pos < buf.len() {
            buf[pos] = b;
            pos += 1;
        }
    }

    let mut num_buf = [0u8; 12];
    let mut num_pos = 0;
    let mut n = value;
    if n == 0 {
        num_buf[0] = b'0';
        num_pos = 1;
    } else {
        while n > 0 && num_pos < 12 {
            num_buf[num_pos] = b'0' + (n % 10) as u8;
            n /= 10;
            num_pos += 1;
        }
    }

    for i in (0..num_pos).rev() {
        if pos < buf.len() {
            buf[pos] = num_buf[i];
            pos += 1;
        }
    }

    log(LogLevel::Info, &buf[..pos]);
}

pub fn redraw_all() {
    let count = LOG_COUNT.load(Ordering::Relaxed);
    redraw_visible(count);
}

pub fn clear() {
    LOG_COUNT.store(0, Ordering::Release);
    let log_height = (MAX_LOG_LINES as u32) * LINE_HEIGHT + 4;
    fill_rect(
        LOG_X - 2,
        LOG_Y_START - 2,
        480,
        log_height,
        COLOR_BACKGROUND,
    );
}
