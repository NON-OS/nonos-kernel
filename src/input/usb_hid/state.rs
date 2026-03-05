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

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use crate::sys::serial;
use super::pci::find_xhci;
use super::xhci::init_xhci;
use super::ring::wait_event;
use super::hid::{self, process_keyboard_report, process_mouse_report, start_hid_poll};

pub(crate) static USB_INIT: AtomicBool = AtomicBool::new(false);
pub(crate) static KBD_AVAIL: AtomicBool = AtomicBool::new(false);
pub(crate) static MOUSE_AVAIL: AtomicBool = AtomicBool::new(false);

pub(crate) static MOUSE_X: AtomicI32 = AtomicI32::new(400);
pub(crate) static MOUSE_Y: AtomicI32 = AtomicI32::new(300);
pub(crate) static MOUSE_BTN: AtomicU8 = AtomicU8::new(0);
pub(crate) static SCR_W: AtomicI32 = AtomicI32::new(800);
pub(crate) static SCR_H: AtomicI32 = AtomicI32::new(600);

pub fn set_screen_bounds(w: u32, h: u32) {
    SCR_W.store(w as i32, Ordering::SeqCst);
    SCR_H.store(h as i32, Ordering::SeqCst);
    MOUSE_X.store((w / 2) as i32, Ordering::SeqCst);
    MOUSE_Y.store((h / 2) as i32, Ordering::SeqCst);
}

pub fn is_available() -> bool { USB_INIT.load(Ordering::Relaxed) }
pub fn keyboard_available() -> bool { KBD_AVAIL.load(Ordering::Relaxed) }
pub fn mouse_available() -> bool { MOUSE_AVAIL.load(Ordering::Relaxed) }

pub fn mouse_position() -> (i32, i32) {
    (MOUSE_X.load(Ordering::Relaxed), MOUSE_Y.load(Ordering::Relaxed))
}

pub fn left_pressed() -> bool { MOUSE_BTN.load(Ordering::Relaxed) & 0x01 != 0 }
pub fn right_pressed() -> bool { MOUSE_BTN.load(Ordering::Relaxed) & 0x02 != 0 }

pub fn init() {
    serial::println(b"[USB] USB HID init...");
    if let Some((_, _, _, bar)) = find_xhci() {
        if bar != 0 && bar < 0xFFFF_FFFF_0000 {
            if init_xhci(bar) {
                serial::println(b"[USB] USB HID ready");
            }
        }
    } else {
        serial::println(b"[USB] No xHCI");
    }
}

pub fn poll_keyboard() -> Option<u8> {
    if !KBD_AVAIL.load(Ordering::Relaxed) { return None; }

    if hid::HID_POLL_PENDING.load(Ordering::Relaxed) {
        if let Some((32, code, _)) = wait_event(100) {
            if code == 1 || code == 13 {
                hid::HID_POLL_PENDING.store(false, Ordering::SeqCst);

                let result = process_keyboard_report();

                start_hid_poll();

                return result;
            }
        }
    } else {
        start_hid_poll();
    }

    let head = hid::KEY_QUEUE_HEAD.load(Ordering::Relaxed);
    let tail = hid::KEY_QUEUE_TAIL.load(Ordering::Relaxed);
    if head != tail {
        // SAFETY: Single-threaded HID processing, no concurrent access to KEY_QUEUE
        let key = unsafe { hid::KEY_QUEUE[head as usize] };
        hid::KEY_QUEUE_HEAD.store((head + 1) & 0x0F, Ordering::SeqCst);
        return Some(key);
    }

    None
}

pub fn poll_mouse() -> bool {
    if !MOUSE_AVAIL.load(Ordering::Relaxed) { return false; }

    if hid::HID_POLL_PENDING.load(Ordering::Relaxed) {
        if let Some((32, code, _)) = wait_event(100) {
            if code == 1 || code == 13 {
                hid::HID_POLL_PENDING.store(false, Ordering::SeqCst);
                process_mouse_report();
                start_hid_poll();
                return true;
            }
        }
    } else {
        start_hid_poll();
    }
    false
}
