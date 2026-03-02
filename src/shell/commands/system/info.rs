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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT};
use crate::sys::timer;
use crate::mem::{heap, pmm};
use crate::input::usb_hid;

pub fn cmd_info() {
    print_line(b"N\xd8NOS Zero State Operating System", COLOR_ACCENT);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Version:   1.0.0-production", COLOR_TEXT);
    print_line(b"Kernel:    Rust microkernel (no_std)", COLOR_TEXT);
    print_line(b"Mode:      ZeroState (RAM-only)", COLOR_GREEN);
    print_line(b"Privacy:   Anonymous by default", COLOR_GREEN);
    print_line(b"Storage:   Ephemeral (no disk)", COLOR_YELLOW);
    print_line(b"", COLOR_TEXT);

    print_line(b"Input Devices:", COLOR_TEXT_WHITE);
    if usb_hid::is_available() {
        print_line(b"  USB HID:    ACTIVE (xHCI)", COLOR_GREEN);
        if usb_hid::keyboard_available() {
            print_line(b"  Keyboard:   USB HID", COLOR_GREEN);
        } else {
            print_line(b"  Keyboard:   PS/2 fallback", COLOR_YELLOW);
        }
        if usb_hid::mouse_available() {
            print_line(b"  Mouse:      USB HID", COLOR_GREEN);
        } else {
            print_line(b"  Mouse:      PS/2 fallback", COLOR_YELLOW);
        }
    } else {
        print_line(b"  USB HID:    Not available", COLOR_YELLOW);
        print_line(b"  Keyboard:   PS/2", COLOR_TEXT);
        print_line(b"  Mouse:      PS/2", COLOR_TEXT);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Subsystems:", COLOR_TEXT_WHITE);
    if timer::is_init() {
        print_line(b"  Timer:      ACTIVE (TSC)", COLOR_GREEN);
    } else {
        print_line(b"  Timer:      Not initialized", COLOR_YELLOW);
    }
    if heap::is_init() {
        print_line(b"  Heap:       ACTIVE", COLOR_GREEN);
    } else {
        print_line(b"  Heap:       Not initialized", COLOR_YELLOW);
    }
    if pmm::is_init() {
        print_line(b"  PMM:        ACTIVE", COLOR_GREEN);
    } else {
        print_line(b"  PMM:        Not initialized", COLOR_YELLOW);
    }
}

pub fn cmd_version() {
    print_line(b"N\xd8NOS Kernel v1.0.0-production", COLOR_ACCENT);
    print_line(b"Built with Rust (no_std)", COLOR_TEXT);
    print_line(b"Target: x86_64-n\xd8nos", COLOR_TEXT);
    print_line(b"License: AGPL-3.0", COLOR_TEXT_DIM);
}

