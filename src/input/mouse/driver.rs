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

use core::sync::atomic::Ordering;
use crate::sys::io::{inb, outb};
use crate::sys::serial;
use super::ps2::{wait_write, wait_read, flush_buffer, mouse_write, mouse_read};
use super::state::{MOUSE_AVAILABLE, SCROLL_WHEEL_AVAILABLE};

pub fn has_scroll_wheel() -> bool {
    SCROLL_WHEEL_AVAILABLE.load(Ordering::Relaxed)
}

pub fn init() {
    serial::println(b"[MOUSE] Initializing PS/2 mouse...");

    // SAFETY: Direct PS/2 controller access for mouse initialization
    unsafe {
        flush_buffer();

        if !wait_write() {
            serial::println(b"[MOUSE] Controller not responding");
            return;
        }
        outb(0x64, 0xA8);

        for _ in 0..10000 { core::hint::spin_loop(); }

        if !wait_write() { return; }
        outb(0x64, 0x20);

        let config = if wait_read() {
            inb(0x60)
        } else {
            serial::println(b"[MOUSE] Failed to read config");
            0x00
        };

        let new_config = (config & !0x20) | 0x02;
        if !wait_write() { return; }
        outb(0x64, 0x60);
        if !wait_write() { return; }
        outb(0x60, new_config);

        serial::println(b"[MOUSE] IRQ12 enabled for mouse");

        let mut mouse_ok = false;

        for attempt in 0..3 {
            if !mouse_write(0xFF) { continue; }

            let mut got_ack = false;
            let mut got_test = false;

            for _ in 0..200_000 {
                if let Some(b) = mouse_read() {
                    if b == 0xFA {
                        got_ack = true;
                    } else if b == 0xAA && got_ack {
                        got_test = true;
                        let _ = mouse_read();
                        break;
                    }
                }
            }

            if got_test {
                serial::println(b"[MOUSE] Reset successful");
                mouse_ok = true;
                break;
            }

            if attempt == 2 {
                serial::println(b"[MOUSE] Reset failed after 3 attempts");
            }
        }

        if !mouse_ok {
            serial::println(b"[MOUSE] Trying without reset...");
        }

        if mouse_write(0xF6) {
            let _ = mouse_read();
        }

        let magic_rates = [200u8, 100, 80];
        for rate in magic_rates {
            if mouse_write(0xF3) {
                let _ = mouse_read();
                if mouse_write(rate) {
                    let _ = mouse_read();
                }
            }
        }

        if mouse_write(0xF2) {
            let _ = mouse_read();
            if let Some(device_id) = mouse_read() {
                if device_id == 3 || device_id == 4 {
                    serial::println(b"[MOUSE] Scroll wheel enabled (IntelliMouse)");
                    SCROLL_WHEEL_AVAILABLE.store(true, Ordering::SeqCst);
                }
            }
        }

        if mouse_write(0xF3) {
            let _ = mouse_read();
            if mouse_write(100) {
                let _ = mouse_read();
            }
        }

        if mouse_write(0xE8) {
            let _ = mouse_read();
            if mouse_write(0x02) {
                let _ = mouse_read();
            }
        }

        if mouse_write(0xF4) {
            if let Some(ack) = mouse_read() {
                if ack == 0xFA {
                    serial::println(b"[MOUSE] Mouse enabled");
                    MOUSE_AVAILABLE.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    serial::println(b"[MOUSE] Init complete");
}
