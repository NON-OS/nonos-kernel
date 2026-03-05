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
use crate::sys::io::inb;
use super::state::{
    MOUSE_X, MOUSE_Y, MOUSE_BUTTONS, SCROLL_DELTA,
    SCREEN_WIDTH, SCREEN_HEIGHT, SCROLL_WHEEL_AVAILABLE,
    PACKET_BYTE0, PACKET_BYTE1, PACKET_BYTE2, PACKET_BYTE3, PACKET_INDEX,
    MOUSE_UPDATED,
};

fn process_packet(has_scroll: bool) -> bool {
    let flags = PACKET_BYTE0.load(Ordering::Relaxed);
    let dx_raw = PACKET_BYTE1.load(Ordering::Relaxed) as i32;
    let dy_raw = PACKET_BYTE2.load(Ordering::Relaxed) as i32;

    let dx = if flags & 0x10 != 0 { dx_raw - 256 } else { dx_raw };
    let dy = if flags & 0x20 != 0 { dy_raw - 256 } else { dy_raw };

    let max_x = SCREEN_WIDTH.load(Ordering::Relaxed);
    let max_y = SCREEN_HEIGHT.load(Ordering::Relaxed);

    let cur_x = MOUSE_X.load(Ordering::Relaxed);
    let cur_y = MOUSE_Y.load(Ordering::Relaxed);

    let new_x = (cur_x + dx).clamp(0, max_x - 1);
    let new_y = (cur_y - dy).clamp(0, max_y - 1);

    MOUSE_X.store(new_x, Ordering::Relaxed);
    MOUSE_Y.store(new_y, Ordering::Relaxed);

    MOUSE_BUTTONS.store(flags & 0x07, Ordering::Relaxed);

    if has_scroll {
        let scroll_raw = PACKET_BYTE3.load(Ordering::Relaxed) as i8;
        let current = SCROLL_DELTA.load(Ordering::Relaxed);
        SCROLL_DELTA.store(current + scroll_raw as i32, Ordering::Relaxed);
    }

    true
}

pub fn poll() -> bool {
    if MOUSE_UPDATED.swap(false, Ordering::Relaxed) {
        return true;
    }

    // SAFETY: Reading PS/2 status port
    let status = unsafe { inb(0x64) };

    if status & 0x01 == 0 {
        return false;
    }

    if status & 0x20 == 0 {
        return false;
    }

    // SAFETY: Reading PS/2 data port
    let data = unsafe { inb(0x60) };

    let idx = PACKET_INDEX.load(Ordering::Relaxed);

    match idx {
        0 => {
            if data & 0x08 == 0 {
                return false;
            }
            PACKET_BYTE0.store(data, Ordering::Relaxed);
            PACKET_INDEX.store(1, Ordering::Relaxed);
        }
        1 => {
            PACKET_BYTE1.store(data, Ordering::Relaxed);
            PACKET_INDEX.store(2, Ordering::Relaxed);
        }
        2 => {
            PACKET_BYTE2.store(data, Ordering::Relaxed);

            if SCROLL_WHEEL_AVAILABLE.load(Ordering::Relaxed) {
                PACKET_INDEX.store(3, Ordering::Relaxed);
            } else {
                PACKET_INDEX.store(0, Ordering::Relaxed);
                return process_packet(false);
            }
        }
        3 => {
            PACKET_BYTE3.store(data, Ordering::Relaxed);
            PACKET_INDEX.store(0, Ordering::Relaxed);
            return process_packet(true);
        }
        _ => {
            PACKET_INDEX.store(0, Ordering::Relaxed);
        }
    }

    false
}
