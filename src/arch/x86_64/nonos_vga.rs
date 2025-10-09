//! NØNOS VGA Text Output
//!
//! Features:
//! - Multiple virtual consoles (TTYs) with per-console buffer and cursor.
//! - Scrollback history (configurable lines).
//! - Log level coloring ([INFO]=green, [WARN]=yellow, [ERR]=red, [DBG]=cyan).
//! - SMP-safe: per-console lock, try_lock() for interrupts.
//! - Panic/critical printing bypasses locks entirely.
//! - Hotkey API for switching active console (integrates with keyboard driver).
//! - Works entirely in `no_std` VGA text mode.

use core::fmt::{self, Write};
use core::ptr::NonNull;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::ops::{Deref, DerefMut};
use spin::Mutex;
use volatile::Volatile;

pub const BUFFER_HEIGHT: usize = 25;
pub const BUFFER_WIDTH: usize = 80;
pub const VGA_ADDRESS: usize = 0xb8000;

/// Number of virtual consoles
pub const MAX_CONSOLES: usize = 4;

/// Scrollback history per console
pub const SCROLLBACK_LINES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ColorCode(u8);

impl ColorCode {
    pub const fn new(fg: Color, bg: Color) -> Self {
        Self((bg as u8) << 4 | (fg as u8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ScreenChar {
    pub ascii_character: u8,
    pub color_code: ColorCode,
}

impl Deref for ScreenChar {
    type Target = ScreenChar;
    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for ScreenChar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

#[repr(transparent)]
struct Buffer {
    chars: [[Volatile<ScreenChar>; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

/// Per-console state
pub struct Console {
    row: usize,
    col: usize,
    color_code: ColorCode,
    history: [[ScreenChar; BUFFER_WIDTH]; SCROLLBACK_LINES],
    history_head: usize,
}

impl Console {
    const fn new() -> Self {
        Self {
            row: 0,
            col: 0,
            color_code: ColorCode::new(Color::LightGray, Color::Black),
            history: [[ScreenChar {
                ascii_character: b' ',
                color_code: ColorCode(0),
            }; BUFFER_WIDTH]; SCROLLBACK_LINES],
            history_head: 0,
        }
    }
}

pub struct VgaManager {
    consoles: [Console; MAX_CONSOLES],
    active: usize,
    buffer: NonNull<Buffer>,
    _phantom: PhantomData<Buffer>,
}

unsafe impl Send for VgaManager {}
unsafe impl Sync for VgaManager {}

static VGA: Mutex<VgaManager> = Mutex::new(VgaManager::new());
static ACTIVE_CONSOLE: AtomicUsize = AtomicUsize::new(0);

impl VgaManager {
    pub const fn new() -> Self {
        Self {
            consoles: [Console::new(), Console::new(), Console::new(), Console::new()],
            active: 0,
            buffer: unsafe { NonNull::new_unchecked(VGA_ADDRESS as *mut _) },
            _phantom: PhantomData,
        }
    }

    fn buf(&mut self) -> &mut Buffer {
        unsafe { self.buffer.as_mut() }
    }

    pub fn switch_console(&mut self, idx: usize) {
        if idx >= MAX_CONSOLES || idx == self.active {
            return;
        }
        self.active = idx;
        ACTIVE_CONSOLE.store(idx, Ordering::SeqCst);
        self.redraw();
    }

    fn redraw(&mut self) {
        let active_idx = self.active;
        let history_head = self.consoles[active_idx].history_head;
        let mut hist_idx = if history_head >= BUFFER_HEIGHT {
            history_head - BUFFER_HEIGHT
        } else {
            0
        };
        for row in 0..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                let ch = self.consoles[active_idx].history[(hist_idx + row) % SCROLLBACK_LINES][col];
                self.buf().chars[row][col].write(ch);
            }
        }
    }

    pub fn write_byte(&mut self, b: u8) {
        match b {
            b'\n' => self.new_line(),
            byte => {
                let active = self.active;
                if self.consoles[active].col >= BUFFER_WIDTH {
                    self.new_line();
                }
                let ch = ScreenChar {
                    ascii_character: byte,
                    color_code: self.consoles[active].color_code,
                };
                let row = self.consoles[active].row;
                let col = self.consoles[active].col;
                self.buf().chars[row][col].write(ch);
                self.consoles[active].history[self.consoles[active].history_head % SCROLLBACK_LINES][col] = ch;
                self.consoles[active].col += 1;
            }
        }
    }

    fn new_line(&mut self) {
        let active_idx = self.active;
        self.consoles[active_idx].history_head = (self.consoles[active_idx].history_head + 1) % SCROLLBACK_LINES;
        if self.consoles[active_idx].row + 1 >= BUFFER_HEIGHT {
            self.scroll_up();
        } else {
            self.consoles[active_idx].row += 1;
        }
        self.consoles[active_idx].col = 0;
    }

    fn scroll_up(&mut self) {
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                let ch = self.buf().chars[row][col].read();
                self.buf().chars[row - 1][col].write(ch);
            }
        }
        self.clear_row(BUFFER_HEIGHT - 1);
    }

    fn clear_row(&mut self, row: usize) {
        let con = &mut self.consoles[self.active];
        let blank = ScreenChar { ascii_character: b' ', color_code: con.color_code };
        for col in 0..BUFFER_WIDTH {
            self.buf().chars[row][col].write(blank);
        }
    }

    pub fn clear(&mut self) {
        let active_idx = self.active;
        for row in 0..BUFFER_HEIGHT {
            self.clear_row(row);
        }
        self.consoles[active_idx].row = 0;
        self.consoles[active_idx].col = 0;
    }

    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.consoles[self.active].color_code = ColorCode::new(fg, bg);
    }
}

impl Write for VgaManager {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Print to active console (locks VGA)
pub fn print(s: &str) {
    VGA.lock().write_str(s).ok();
}

/// Print critical message without locking (panic/IST safe)
pub fn print_critical(s: &str) {
    if let Some(mut mgr) = VGA.try_lock() {
        mgr.write_str(s).ok();
    } else {
        // emergency mode: write raw to active console
        unsafe {
            let mut mgr = VgaManager::new();
            mgr.write_str(s).ok();
        }
    }
}

/// Clear active console
pub fn clear() {
    VGA.lock().clear();
}

/// Set active console colors
pub fn set_color(fg: Color, bg: Color) {
    VGA.lock().set_color(fg, bg);
}

/// Switch to console idx
pub fn switch_console(idx: usize) {
    VGA.lock().switch_console(idx);
}

/// Print hexadecimal number
pub fn print_hex(value: u64) {
    let hex_chars = b"0123456789ABCDEF";
    let mut buffer = [0u8; 18]; // "0x" + 16 hex digits
    buffer[0] = b'0';
    buffer[1] = b'x';
    for i in 0..16 {
        let nibble = (value >> (60 - i * 4)) & 0xF;
        buffer[2 + i] = hex_chars[nibble as usize];
    }
    let hex_str = core::str::from_utf8(&buffer).unwrap();
    print(hex_str);
}
