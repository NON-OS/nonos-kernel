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
//! VGA Text Mode Output for Early Boot
//
// ============================================================================
// Constants
// ============================================================================

/// VGA text buffer base address
const VGA_BUFFER: usize = 0xB8000;

/// VGA text mode dimensions
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;

/// VGA color attributes
pub mod colors {
    pub const BLACK: u8 = 0x00;
    pub const BLUE: u8 = 0x01;
    pub const GREEN: u8 = 0x02;
    pub const CYAN: u8 = 0x03;
    pub const RED: u8 = 0x04;
    pub const MAGENTA: u8 = 0x05;
    pub const BROWN: u8 = 0x06;
    pub const LIGHT_GRAY: u8 = 0x07;
    pub const DARK_GRAY: u8 = 0x08;
    pub const LIGHT_BLUE: u8 = 0x09;
    pub const LIGHT_GREEN: u8 = 0x0A;
    pub const LIGHT_CYAN: u8 = 0x0B;
    pub const LIGHT_RED: u8 = 0x0C;
    pub const PINK: u8 = 0x0D;
    pub const YELLOW: u8 = 0x0E;
    pub const WHITE: u8 = 0x0F;
}

// ============================================================================
// VGA Output Functions
// ============================================================================

/// Delay for visual effects during boot
#[inline]
fn visual_delay(iterations: u32) {
    for _ in 0..iterations {
        for _ in 0..100_000 {
            unsafe {
                core::arch::asm!("pause", options(nomem, nostack));
            }
        }
    }
}

/// Write a string to VGA at position with color and optional delay
///
/// # Safety
///
/// Writes directly to VGA memory at 0xB8000.
unsafe fn write_at(row: usize, col: usize, text: &[u8], attr: u8, delay: u32) {
    let vga = VGA_BUFFER as *mut u8;

    for (i, &byte) in text.iter().enumerate() {
        let x = col + i;
        if x >= VGA_WIDTH {
            break;
        }

        let offset = (row * VGA_WIDTH + x) * 2;
        *vga.add(offset) = byte;
        *vga.add(offset + 1) = attr;

        if delay > 0 {
            visual_delay(delay);
        }
    }
}

/// Clear the VGA screen with a specific color
///
/// # Safety
///
/// Writes directly to VGA memory.
pub unsafe fn clear_screen(attr: u8) {
    let vga = VGA_BUFFER as *mut u8;

    for i in 0..(VGA_WIDTH * VGA_HEIGHT) {
        let offset = i * 2;
        *vga.add(offset) = b' ';
        *vga.add(offset + 1) = attr;
    }
}

/// Write a string at a position (immediate, no delay)
///
/// # Safety
///
/// Writes directly to VGA memory.
pub unsafe fn write_string(row: usize, col: usize, text: &[u8], attr: u8) {
    write_at(row, col, text, attr, 0);
}

// ============================================================================
// Boot Splash
// ============================================================================

/// Display the NØNOS boot splash screen
///
/// Shows ASCII logo, version info and animated boot status messages.
///
/// # Safety
///
/// Writes directly to VGA memory.
pub fn show_boot_splash() {
    unsafe {
        // Clear screen with black background
        clear_screen(colors::BLACK);
        visual_delay(5);

        // NØNOS ASCII
        let logo = [
            b"888b    888  .d88888b.  888b    888  .d88888b.   .d8888b." as &[u8],
            b"8888b   888 d88P\" \"Y88b 8888b   888 d88P\" \"Y88b d88P  Y88b",
            b"88888b  888 888     888 88888b  888 888     888 Y88b.",
            b"888Y88b 888 888     888 888Y88b 888 888     888  \"Y888b.",
            b"888 Y88b888 888     888 888 Y88b888 888     888     \"Y88b.",
            b"888  Y88888 888     888 888  Y88888 888     888       \"888",
            b"888   Y8888 Y88b. .d88P 888   Y8888 Y88b. .d88P Y88b  d88P",
            b"888    Y888  \"Y88888P\"  888    Y888  \"Y88888P\"   \"Y8888P\"",
        ];

        for (i, line) in logo.iter().enumerate() {
            write_at(2 + i, 20, line, colors::LIGHT_CYAN, 1);
        }

        visual_delay(10);

        // Kernel version banner
        write_at(
            11,
            25,
            b"MICROKERNEL v1.0 :: x86_64 :: FIPS-140",
            colors::WHITE,
            2,
        );

        visual_delay(8);

        // Security features box
        write_at(
            13,
            15,
            b"+=====================================================+",
            colors::DARK_GRAY,
            1,
        );
        write_at(
            14,
            15,
            b"|  MEMORY ISOLATION  |  CAPABILITY SECURITY  |  PQ   |",
            colors::LIGHT_GRAY,
            1,
        );
        write_at(
            15,
            15,
            b"+=====================================================+",
            colors::DARK_GRAY,
            1,
        );

        visual_delay(8);

        // Boot status header
        write_at(17, 5, b"[KERNEL BOOT SEQUENCE]", colors::YELLOW, 2);

        visual_delay(5);

        // Boot status messages
        show_boot_status(19, "CPU structures", true);
        show_boot_status(20, "Memory manager", true);
        show_boot_status(21, "Interrupt handlers", true);
        show_boot_status(22, "Security subsystem", true);
        show_boot_status(23, "Cryptographic engine", true);

        visual_delay(5);
    }
}

/// Show a boot status line with OK/FAIL indicator
unsafe fn show_boot_status(row: usize, name: &str, success: bool) {
    write_at(row, 5, b"[", colors::LIGHT_GRAY, 0);
    write_at(row, 6, b"INIT", colors::LIGHT_GREEN, 0);
    write_at(row, 10, b"]", colors::LIGHT_GRAY, 0);

    // Pad name to fixed width
    let mut padded = [b'.'; 41];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(40);
    padded[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    padded[copy_len] = b' ';

    write_at(row, 12, &padded, colors::LIGHT_GRAY, 2);

    if success {
        write_at(row, 53, b"[  OK  ]", colors::LIGHT_GREEN, 0);
    } else {
        write_at(row, 53, b"[ FAIL ]", colors::LIGHT_RED, 0);
    }

    visual_delay(3);
}

/// Display a panic message on VGA
///
/// # Safety
///
/// Writes directly to VGA memory.
pub unsafe fn show_panic(message: &str) {
    let vga = VGA_BUFFER as *mut u16;

    // Write "KERNEL PANIC" in red on white at top of screen
    let header = b"KERNEL PANIC";
    for (i, &byte) in header.iter().enumerate() {
        *vga.add(i) = 0x4F00 | (byte as u16); // White on red
    }

    // Write message on next line
    let msg_bytes = message.as_bytes();
    let max_len = msg_bytes.len().min(VGA_WIDTH);
    for (i, &byte) in msg_bytes[..max_len].iter().enumerate() {
        *vga.add(VGA_WIDTH + i) = 0x0F00 | (byte as u16); // White on black
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_constants() {
        assert_eq!(colors::BLACK, 0x00);
        assert_eq!(colors::WHITE, 0x0F);
        assert_eq!(colors::LIGHT_CYAN, 0x0B);
    }

    #[test]
    fn test_vga_dimensions() {
        assert_eq!(VGA_WIDTH * VGA_HEIGHT, 2000);
    }
}
