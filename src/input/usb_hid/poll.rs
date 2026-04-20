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
use super::state::{KBD_AVAIL, MOUSE_AVAIL, TABLET_MODE};
use super::hid::{HID_POLL_PENDING, KEY_QUEUE, KEY_QUEUE_HEAD, KEY_QUEUE_TAIL};
use super::hid::{process_keyboard_report, process_mouse_report, start_hid_poll};
use super::ring::{wait_event, check_event};

pub fn poll_keyboard() -> Option<u8> {
    if !KBD_AVAIL.load(Ordering::Relaxed) { return None; }
    // In tablet mode the single HID endpoint sends pointer reports,
    // not keyboard reports. Let poll_mouse() drive the HID polling
    // so it doesn't steal Transfer Events meant for mouse data.
    if !TABLET_MODE.load(Ordering::Relaxed) {
        if HID_POLL_PENDING.load(Ordering::Relaxed) {
            if let Some((32, code, _)) = wait_event(100) {
                if code == 1 || code == 13 {
                    HID_POLL_PENDING.store(false, Ordering::SeqCst);
                    let result = process_keyboard_report();
                    start_hid_poll();
                    return result;
                }
            }
        } else {
            start_hid_poll();
        }
    }
    let head = KEY_QUEUE_HEAD.load(Ordering::Relaxed);
    let tail = KEY_QUEUE_TAIL.load(Ordering::Relaxed);
    if head != tail {
        let key = unsafe { KEY_QUEUE[head as usize] };
        KEY_QUEUE_HEAD.store((head + 1) & 0x0F, Ordering::SeqCst);
        return Some(key);
    }
    None
}

pub fn poll_mouse() -> bool {
    if !MOUSE_AVAIL.load(Ordering::Relaxed) { return false; }

    // Drain any ready events from the event ring (non-blocking).
    // Multiple events can accumulate between desktop loop iterations.
    if HID_POLL_PENDING.load(Ordering::Relaxed) {
        for _ in 0..8 {
            match check_event() {
                Some((32, code, _)) => {
                    // Transfer Event — ANY completion code means the TRB was
                    // consumed by the xHCI controller, so we must clear the
                    // pending flag and re-queue regardless of success/error.
                    HID_POLL_PENDING.store(false, Ordering::SeqCst);
                    if code == 1 || code == 13 {
                        // Success or Short Packet — process the HID report
                        process_mouse_report();
                    }
                    start_hid_poll();
                    return code == 1 || code == 13;
                }
                Some(_) => {
                    // Non-transfer event (e.g. Port Status Change) — consume
                    // it and check the next slot immediately.
                    continue;
                }
                None => break, // No more events ready
            }
        }
    } else {
        start_hid_poll();
    }
    false
}
