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

use super::colors;
use super::output::{clear_screen, visual_delay, write_at, VGA_WIDTH};

pub fn show_boot_splash() {
    // # SAFETY: Writing to VGA memory for boot splash display
    unsafe {
        clear_screen(colors::BLACK);
        visual_delay(5);

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

        write_at(11, 25, b"MICROKERNEL v1.0 :: x86_64 :: FIPS-140", colors::WHITE, 2);

        visual_delay(8);

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

        write_at(17, 5, b"[KERNEL BOOT SEQUENCE]", colors::YELLOW, 2);

        visual_delay(5);

        show_boot_status(19, "CPU structures", true);
        show_boot_status(20, "Memory manager", true);
        show_boot_status(21, "Interrupt handlers", true);
        show_boot_status(22, "Security subsystem", true);
        show_boot_status(23, "Cryptographic engine", true);

        visual_delay(5);
    }
}

/// # Safety: Writes directly to VGA memory.
unsafe fn show_boot_status(row: usize, name: &str, success: bool) { unsafe {
    write_at(row, 5, b"[", colors::LIGHT_GRAY, 0);
    write_at(row, 6, b"INIT", colors::LIGHT_GREEN, 0);
    write_at(row, 10, b"]", colors::LIGHT_GRAY, 0);

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
}}

/// # Safety; Writes directly to VGA memory.
pub unsafe fn show_panic(message: &str) { unsafe {
    use super::output::VGA_BUFFER;
    let vga = VGA_BUFFER as *mut u16;
    let header = b"KERNEL PANIC";
    for (i, &byte) in header.iter().enumerate() {
        *vga.add(i) = 0x4F00 | (byte as u16);
    }

    let msg_bytes = message.as_bytes();
    let max_len = msg_bytes.len().min(VGA_WIDTH);
    for (i, &byte) in msg_bytes[..max_len].iter().enumerate() {
        *vga.add(VGA_WIDTH + i) = 0x0F00 | (byte as u16);
    }
}}

pub fn show_status_line(row: usize, prefix: &str, message: &str, attr: u8) {
    // # SAFETY: Writing to VGA memory
    unsafe {
        let prefix_bytes = prefix.as_bytes();
        let msg_bytes = message.as_bytes();
        write_at(row, 0, prefix_bytes, colors::LIGHT_GREEN, 0);
        write_at(row, prefix_bytes.len() + 1, msg_bytes, attr, 0);
    }
}

pub fn show_progress(row: usize, current: usize, total: usize) {
    // # SAFETY: Writing to VGA memory
    unsafe {
        let bar_width = 50;
        let filled = if total > 0 { (current * bar_width) / total } else { 0 };
        write_at(row, 5, b"[", colors::LIGHT_GRAY, 0);
        for i in 0..bar_width {
            let ch = if i < filled { b'=' } else { b' ' };
            write_at(row, 6 + i, &[ch], colors::LIGHT_CYAN, 0);
        }

        write_at(row, 6 + bar_width, b"]", colors::LIGHT_GRAY, 0);
        let percent = if total > 0 { (current * 100) / total } else { 0 };
        let mut pct_buf = [b' '; 5];
        if percent >= 100 {
            pct_buf[0] = b'1';
            pct_buf[1] = b'0';
            pct_buf[2] = b'0';
        } else if percent >= 10 {
            pct_buf[0] = b' ';
            pct_buf[1] = b'0' + (percent / 10) as u8;
            pct_buf[2] = b'0' + (percent % 10) as u8;
        } else {
            pct_buf[0] = b' ';
            pct_buf[1] = b' ';
            pct_buf[2] = b'0' + percent as u8;
        }
        pct_buf[3] = b'%';
        write_at(row, 8 + bar_width, &pct_buf, colors::WHITE, 0);
    }
}
