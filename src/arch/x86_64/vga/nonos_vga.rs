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
// 
// NØNOS x86_64 VGA Text Mode Driver
// Architecture:
// ┌───────────────────────────────────────────────────────┐
// │                      VGA Text Mode Memory             │
// ├───────────────────────────────────────────────────────┤
// │  Base Address: 0xB8000                                │
// │  Size: 80 columns × 25 rows × 2 bytes = 4000 bytes    │
// │                                                       │
// │  Character Format (2 bytes):                          │
// │  ┌────────────────────────────────────────────────────┐   
// │  │  Byte 0: ASCII character code                      │   
// │  │  Byte 1: Attribute byte                            │   
// │  │          ┌─────┬───────────┬───────────┐           │   
// │  │          │Blink│ Background│ Foreground│           │   
// │  │          │ (1) │   (3)     │   (4)     │           │   
// │  │          └─────┴───────────┴───────────┘           │   
// │  └────────────────────────────────────────────────────┘   
// │                                                       │
// │  CRT Controller Registers (I/O ports):                │
// │  - 0x3D4: Index register                              │
// │  - 0x3D5: Data register                               │
// │  - Cursor registers: 0x0E (high), 0x0F (low)          │
// └───────────────────────────────────────────────────────┘

use core::arch::asm;
use core::fmt::{self, Write};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

// ============================================================================
// Error Types
// ============================================================================

/// VGA operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VgaError {
    /// No error
    None = 0,
    /// Not initialized
    NotInitialized = 1,
    /// Already initialized
    AlreadyInitialized = 2,
    /// Invalid console index
    InvalidConsole = 3,
    /// Invalid position
    InvalidPosition = 4,
    /// Lock contention
    LockContention = 5,
}

impl VgaError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::NotInitialized => "VGA not initialized",
            Self::AlreadyInitialized => "VGA already initialized",
            Self::InvalidConsole => "invalid console index",
            Self::InvalidPosition => "invalid cursor position",
            Self::LockContention => "VGA lock contention",
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// VGA text buffer base address
pub const VGA_BUFFER_ADDR: usize = 0xB8000;

/// Screen width in characters
pub const SCREEN_WIDTH: usize = 80;

/// Screen height in characters
pub const SCREEN_HEIGHT: usize = 25;

/// Total screen characters
pub const SCREEN_SIZE: usize = SCREEN_WIDTH * SCREEN_HEIGHT;

/// Bytes per character (character + attribute)
pub const BYTES_PER_CHAR: usize = 2;

/// Total VGA buffer size
pub const VGA_BUFFER_SIZE: usize = SCREEN_SIZE * BYTES_PER_CHAR;

/// Maximum virtual consoles
pub const MAX_CONSOLES: usize = 4;

/// Scrollback buffer lines per console
pub const SCROLLBACK_LINES: usize = 200;

/// CRT Controller index port
const CRT_INDEX: u16 = 0x3D4;

/// CRT Controller data port
const CRT_DATA: u16 = 0x3D5;

/// Cursor location high register
const CURSOR_HIGH: u8 = 0x0E;

/// Cursor location low register
const CURSOR_LOW: u8 = 0x0F;

/// Cursor start register
const CURSOR_START: u8 = 0x0A;

/// Cursor end register
const CURSOR_END: u8 = 0x0B;

// ============================================================================
// Colors
// ============================================================================

/// VGA text mode colors
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

impl Color {
    /// Get color name
    pub const fn name(self) -> &'static str {
        match self {
            Self::Black => "Black",
            Self::Blue => "Blue",
            Self::Green => "Green",
            Self::Cyan => "Cyan",
            Self::Red => "Red",
            Self::Magenta => "Magenta",
            Self::Brown => "Brown",
            Self::LightGray => "LightGray",
            Self::DarkGray => "DarkGray",
            Self::LightBlue => "LightBlue",
            Self::LightGreen => "LightGreen",
            Self::LightCyan => "LightCyan",
            Self::LightRed => "LightRed",
            Self::Pink => "Pink",
            Self::Yellow => "Yellow",
            Self::White => "White",
        }
    }
}

/// Color attribute byte
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ColorCode(u8);

impl ColorCode {
    /// Create color code from foreground and background
    pub const fn new(foreground: Color, background: Color) -> Self {
        Self((background as u8) << 4 | (foreground as u8))
    }

    /// Create with blink enabled
    pub const fn with_blink(foreground: Color, background: Color) -> Self {
        Self(0x80 | (background as u8) << 4 | (foreground as u8))
    }

    /// Get foreground color
    pub const fn foreground(self) -> u8 {
        self.0 & 0x0F
    }

    /// Get background color
    pub const fn background(self) -> u8 {
        (self.0 >> 4) & 0x07
    }

    /// Check if blinking
    pub const fn is_blinking(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Get raw value
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl Default for ColorCode {
    fn default() -> Self {
        Self::new(Color::LightGray, Color::Black)
    }
}

// ============================================================================
// Screen Character
// ============================================================================

/// VGA screen character (2 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ScreenChar {
    /// ASCII character
    pub character: u8,
    /// Color attribute
    pub color: ColorCode,
}

impl ScreenChar {
    /// Create new screen character
    pub const fn new(character: u8, color: ColorCode) -> Self {
        Self { character, color }
    }

    /// Create blank character with color
    pub const fn blank(color: ColorCode) -> Self {
        Self {
            character: b' ',
            color,
        }
    }

    /// Get as u16 for writing
    pub const fn as_u16(self) -> u16 {
        (self.color.value() as u16) << 8 | (self.character as u16)
    }
}

impl Default for ScreenChar {
    fn default() -> Self {
        Self::blank(ColorCode::default())
    }
}

// ============================================================================
// Console State
// ============================================================================

/// Per-console state
pub struct Console {
    /// Cursor row (0-24)
    row: usize,
    /// Cursor column (0-79)
    col: usize,
    /// Current color
    color: ColorCode,
    /// Screen buffer (current view)
    buffer: [[ScreenChar; SCREEN_WIDTH]; SCREEN_HEIGHT],
    /// Scrollback history
    history: [[ScreenChar; SCREEN_WIDTH]; SCROLLBACK_LINES],
    /// History write position
    history_pos: usize,
    /// Characters written
    chars_written: u64,
}

impl Console {
    /// Create new console
    pub const fn new() -> Self {
        Self {
            row: 0,
            col: 0,
            color: ColorCode::new(Color::LightGray, Color::Black),
            buffer: [[ScreenChar::new(b' ', ColorCode::new(Color::LightGray, Color::Black)); SCREEN_WIDTH]; SCREEN_HEIGHT],
            history: [[ScreenChar::new(b' ', ColorCode::new(Color::LightGray, Color::Black)); SCREEN_WIDTH]; SCROLLBACK_LINES],
            history_pos: 0,
            chars_written: 0,
        }
    }

    /// Clear console
    pub fn clear(&mut self) {
        let blank = ScreenChar::blank(self.color);
        for row in 0..SCREEN_HEIGHT {
            for col in 0..SCREEN_WIDTH {
                self.buffer[row][col] = blank;
            }
        }
        self.row = 0;
        self.col = 0;
    }

    /// Set color
    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = ColorCode::new(fg, bg);
    }

    /// Write a byte
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.col = 0,
            b'\t' => {
                let spaces = 4 - (self.col % 4);
                for _ in 0..spaces {
                    self.write_byte(b' ');
                }
            }
            0x08 => {
                // Backspace
                if self.col > 0 {
                    self.col -= 1;
                    self.buffer[self.row][self.col] = ScreenChar::blank(self.color);
                }
            }
            byte => {
                if self.col >= SCREEN_WIDTH {
                    self.newline();
                }

                let sc = ScreenChar::new(byte, self.color);
                self.buffer[self.row][self.col] = sc;
                self.col += 1;
                self.chars_written += 1;
            }
        }
    }

    /// Handle newline
    fn newline(&mut self) {
        // Save current line to history
        self.history[self.history_pos] = self.buffer[self.row];
        self.history_pos = (self.history_pos + 1) % SCROLLBACK_LINES;

        if self.row + 1 >= SCREEN_HEIGHT {
            self.scroll_up();
        } else {
            self.row += 1;
        }
        self.col = 0;
    }

    /// Scroll screen up one line
    fn scroll_up(&mut self) {
        for row in 1..SCREEN_HEIGHT {
            self.buffer[row - 1] = self.buffer[row];
        }
        // Clear last row
        let blank = ScreenChar::blank(self.color);
        for col in 0..SCREEN_WIDTH {
            self.buffer[SCREEN_HEIGHT - 1][col] = blank;
        }
    }

    /// Copy buffer to VGA memory
    pub fn flush_to_vga(&self) {
        unsafe {
            let vga = VGA_BUFFER_ADDR as *mut u16;
            for row in 0..SCREEN_HEIGHT {
                for col in 0..SCREEN_WIDTH {
                    let offset = row * SCREEN_WIDTH + col;
                    ptr::write_volatile(vga.add(offset), self.buffer[row][col].as_u16());
                }
            }
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Console array
static mut CONSOLES: [Console; MAX_CONSOLES] = [
    Console::new(),
    Console::new(),
    Console::new(),
    Console::new(),
];

/// Active console index
static ACTIVE_CONSOLE: AtomicUsize = AtomicUsize::new(0);

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Simple spinlock for VGA access
static VGA_LOCK: AtomicBool = AtomicBool::new(false);

/// Panic mode (bypass locks)
static PANIC_MODE: AtomicBool = AtomicBool::new(false);

/// Statistics
static CHARS_WRITTEN: AtomicU64 = AtomicU64::new(0);
static LINES_SCROLLED: AtomicU64 = AtomicU64::new(0);
static CONSOLE_SWITCHES: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Port I/O
// ============================================================================

#[inline]
unsafe fn outb(port: u16, value: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

// ============================================================================
// Lock Management
// ============================================================================

/// Acquire VGA lock
fn acquire_lock() -> bool {
    if PANIC_MODE.load(Ordering::Relaxed) {
        return true; // Skip lock in panic mode
    }

    // Try to acquire
    let mut attempts = 0;
    while VGA_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        attempts += 1;
        if attempts > 1000 {
            return false; // Give up
        }
        core::hint::spin_loop();
    }
    true
}

/// Release VGA lock
fn release_lock() {
    if !PANIC_MODE.load(Ordering::Relaxed) {
        VGA_LOCK.store(false, Ordering::Release);
    }
}

// ============================================================================
// Hardware Cursor
// ============================================================================

/// Update hardware cursor position
pub fn update_cursor(row: usize, col: usize) {
    if row >= SCREEN_HEIGHT || col >= SCREEN_WIDTH {
        return;
    }

    let pos = (row * SCREEN_WIDTH + col) as u16;

    unsafe {
        outb(CRT_INDEX, CURSOR_HIGH);
        outb(CRT_DATA, (pos >> 8) as u8);
        outb(CRT_INDEX, CURSOR_LOW);
        outb(CRT_DATA, (pos & 0xFF) as u8);
    }
}

/// Enable hardware cursor
pub fn enable_cursor(start: u8, end: u8) {
    unsafe {
        outb(CRT_INDEX, CURSOR_START);
        let current = inb(CRT_DATA);
        outb(CRT_DATA, (current & 0xC0) | start);

        outb(CRT_INDEX, CURSOR_END);
        let current = inb(CRT_DATA);
        outb(CRT_DATA, (current & 0xE0) | end);
    }
}

/// Disable hardware cursor
pub fn disable_cursor() {
    unsafe {
        outb(CRT_INDEX, CURSOR_START);
        outb(CRT_DATA, 0x20); // Bit 5 = cursor disabled
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize VGA subsystem
pub fn init() -> Result<(), VgaError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(VgaError::AlreadyInitialized);
    }

    // Clear all consoles
    unsafe {
        for console in &mut CONSOLES {
            console.clear();
        }
    }

    // Enable cursor (standard block cursor)
    enable_cursor(14, 15);

    // Flush initial state
    unsafe {
        CONSOLES[0].flush_to_vga();
    }

    update_cursor(0, 0);

    Ok(())
}

/// Check if initialized
#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Enter panic mode (bypass locks)
pub fn enter_panic_mode() {
    PANIC_MODE.store(true, Ordering::Release);
}

// ============================================================================
// Console Operations
// ============================================================================

/// Get active console index
pub fn active_console() -> usize {
    ACTIVE_CONSOLE.load(Ordering::Acquire)
}

/// Switch to console
pub fn switch_console(index: usize) -> Result<(), VgaError> {
    if index >= MAX_CONSOLES {
        return Err(VgaError::InvalidConsole);
    }

    if !acquire_lock() {
        return Err(VgaError::LockContention);
    }

    ACTIVE_CONSOLE.store(index, Ordering::Release);
    CONSOLE_SWITCHES.fetch_add(1, Ordering::Relaxed);

    unsafe {
        CONSOLES[index].flush_to_vga();
        update_cursor(CONSOLES[index].row, CONSOLES[index].col);
    }

    release_lock();
    Ok(())
}

/// Write byte to active console
pub fn write_byte(byte: u8) {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    unsafe {
        CONSOLES[index].write_byte(byte);
        CONSOLES[index].flush_to_vga();
        update_cursor(CONSOLES[index].row, CONSOLES[index].col);
    }
    CHARS_WRITTEN.fetch_add(1, Ordering::Relaxed);

    release_lock();
}

/// Write string to active console
pub fn write_str(s: &str) {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    unsafe {
        for byte in s.bytes() {
            CONSOLES[index].write_byte(byte);
        }
        CONSOLES[index].flush_to_vga();
        update_cursor(CONSOLES[index].row, CONSOLES[index].col);
    }
    CHARS_WRITTEN.fetch_add(s.len() as u64, Ordering::Relaxed);

    release_lock();
}

/// Write string to specific console
pub fn write_str_to_console(index: usize, s: &str) -> Result<(), VgaError> {
    if index >= MAX_CONSOLES {
        return Err(VgaError::InvalidConsole);
    }

    if !acquire_lock() {
        return Err(VgaError::LockContention);
    }

    unsafe {
        for byte in s.bytes() {
            CONSOLES[index].write_byte(byte);
        }

        // Only flush if this is the active console
        if index == ACTIVE_CONSOLE.load(Ordering::Relaxed) {
            CONSOLES[index].flush_to_vga();
            update_cursor(CONSOLES[index].row, CONSOLES[index].col);
        }
    }

    release_lock();
    Ok(())
}

/// Clear active console
pub fn clear() {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    unsafe {
        CONSOLES[index].clear();
        CONSOLES[index].flush_to_vga();
        update_cursor(0, 0);
    }

    release_lock();
}

/// Set color for active console
pub fn set_color(fg: Color, bg: Color) {
    if !acquire_lock() {
        return;
    }

    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    unsafe {
        CONSOLES[index].set_color(fg, bg);
    }

    release_lock();
}

/// Print critical message (panic-safe, bypasses locks)
pub fn print_critical(s: &str) {
    let index = ACTIVE_CONSOLE.load(Ordering::Relaxed);
    unsafe {
        for byte in s.bytes() {
            CONSOLES[index].write_byte(byte);
        }
        CONSOLES[index].flush_to_vga();
    }
}

/// Print hex value
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

// ============================================================================
// Writer Implementation
// ============================================================================

/// VGA writer for fmt::Write trait
pub struct VgaWriter {
    console: usize,
}

impl VgaWriter {
    /// Create writer for active console
    pub fn new() -> Self {
        Self {
            console: ACTIVE_CONSOLE.load(Ordering::Acquire),
        }
    }

    /// Create writer for specific console
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

// ============================================================================
// Statistics
// ============================================================================

/// VGA statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct VgaStats {
    /// Total characters written
    pub chars_written: u64,
    /// Total lines scrolled
    pub lines_scrolled: u64,
    /// Console switches
    pub console_switches: u64,
    /// Active console
    pub active_console: usize,
    /// Initialized flag
    pub initialized: bool,
}

/// Get VGA statistics
pub fn get_stats() -> VgaStats {
    VgaStats {
        chars_written: CHARS_WRITTEN.load(Ordering::Relaxed),
        lines_scrolled: LINES_SCROLLED.load(Ordering::Relaxed),
        console_switches: CONSOLE_SWITCHES.load(Ordering::Relaxed),
        active_console: ACTIVE_CONSOLE.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(VgaError::None.as_str(), "no error");
        assert_eq!(VgaError::NotInitialized.as_str(), "VGA not initialized");
    }

    #[test]
    fn test_color_names() {
        assert_eq!(Color::Black.name(), "Black");
        assert_eq!(Color::White.name(), "White");
    }

    #[test]
    fn test_color_code() {
        let cc = ColorCode::new(Color::White, Color::Blue);
        assert_eq!(cc.foreground(), 15);
        assert_eq!(cc.background(), 1);
        assert!(!cc.is_blinking());
    }

    #[test]
    fn test_screen_char() {
        let sc = ScreenChar::new(b'A', ColorCode::default());
        assert_eq!(sc.character, b'A');
    }

    #[test]
    fn test_constants() {
        assert_eq!(SCREEN_WIDTH, 80);
        assert_eq!(SCREEN_HEIGHT, 25);
        assert_eq!(SCREEN_SIZE, 2000);
    }
}
