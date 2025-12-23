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
// NØNOS x86_64 VGA Module

pub mod nonos_vga;

// ============================================================================
// Error Types
// ============================================================================

pub use nonos_vga::VgaError;

// ============================================================================
// Constants
// ============================================================================

pub use nonos_vga::VGA_BUFFER_ADDR;
pub use nonos_vga::SCREEN_WIDTH;
pub use nonos_vga::SCREEN_HEIGHT;
pub use nonos_vga::SCREEN_SIZE;
pub use nonos_vga::MAX_CONSOLES;
pub use nonos_vga::SCROLLBACK_LINES;

// ============================================================================
// Types
// ============================================================================

pub use nonos_vga::Color;
pub use nonos_vga::ColorCode;
pub use nonos_vga::ScreenChar;
pub use nonos_vga::VgaStats;
pub use nonos_vga::VgaWriter;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize VGA subsystem
#[inline]
pub fn init() -> Result<(), VgaError> {
    nonos_vga::init()
}

/// Check if initialized
#[inline]
pub fn is_initialized() -> bool {
    nonos_vga::is_initialized()
}

/// Enter panic mode
#[inline]
pub fn enter_panic_mode() {
    nonos_vga::enter_panic_mode()
}

// ============================================================================
// Console Operations
// ============================================================================

/// Get active console index
#[inline]
pub fn active_console() -> usize {
    nonos_vga::active_console()
}

/// Switch to console
#[inline]
pub fn switch_console(index: usize) -> Result<(), VgaError> {
    nonos_vga::switch_console(index)
}

// ============================================================================
// Display Operations
// ============================================================================

/// Write byte to active console
#[inline]
pub fn write_byte(byte: u8) {
    nonos_vga::write_byte(byte)
}

/// Write string to active console
#[inline]
pub fn write_str(s: &str) {
    nonos_vga::write_str(s)
}

/// Write string to specific console
#[inline]
pub fn write_str_to_console(index: usize, s: &str) -> Result<(), VgaError> {
    nonos_vga::write_str_to_console(index, s)
}

/// Clear active console
#[inline]
pub fn clear() {
    nonos_vga::clear()
}

/// Set color for active console
#[inline]
pub fn set_color(fg: Color, bg: Color) {
    nonos_vga::set_color(fg, bg)
}

/// Print critical message (panic-safe)
#[inline]
pub fn print_critical(s: &str) {
    nonos_vga::print_critical(s)
}

/// Print hex value
#[inline]
pub fn print_hex(value: u64) {
    nonos_vga::print_hex(value)
}

/// Print a string (alias for write_str)
#[inline]
pub fn print(s: &str) {
    nonos_vga::write_str(s)
}

// ============================================================================
// Cursor Operations
// ============================================================================

/// Update hardware cursor position
#[inline]
pub fn update_cursor(row: usize, col: usize) {
    nonos_vga::update_cursor(row, col)
}

/// Enable hardware cursor
#[inline]
pub fn enable_cursor(start: u8, end: u8) {
    nonos_vga::enable_cursor(start, end)
}

/// Disable hardware cursor
#[inline]
pub fn disable_cursor() {
    nonos_vga::disable_cursor()
}

// ============================================================================
// Statistics
// ============================================================================

/// Get VGA statistics
#[inline]
pub fn get_stats() -> VgaStats {
    nonos_vga::get_stats()
}
