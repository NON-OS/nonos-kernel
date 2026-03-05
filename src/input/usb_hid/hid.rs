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

//! HID report processing and keyboard/mouse handling

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use super::ring::{queue_hid, ring_db};
use super::xhci::{SLOT_ID, HID_EP_DCI, MAX_PACKET};
use super::{MOUSE_X, MOUSE_Y, MOUSE_BTN, SCR_W, SCR_H};

// =============================================================================
// TRB Constants
// =============================================================================

const TRB_TYPE_NORMAL: u32 = 1;
const TRB_IOC: u32 = 1 << 5;
const TRB_ISP: u32 = 1 << 2;

// =============================================================================
// HID Report Buffers
// =============================================================================

#[repr(C, align(64))]
pub(crate) struct HidReports {
    pub kbd: [u8; 8],
    pub mouse: [u8; 8],
}
pub(crate) static mut HID_REPORTS: HidReports = HidReports { kbd: [0; 8], mouse: [0; 8] };

// =============================================================================
// Keyboard State
// =============================================================================

pub(crate) static mut PREV_KEYS: [u8; 6] = [0; 6];
pub(crate) static KEY_MOD: AtomicU8 = AtomicU8::new(0);
pub(crate) static mut KEY_QUEUE: [u8; 16] = [0; 16];
pub(crate) static KEY_QUEUE_HEAD: AtomicU8 = AtomicU8::new(0);
pub(crate) static KEY_QUEUE_TAIL: AtomicU8 = AtomicU8::new(0);

pub(crate) static HID_POLL_PENDING: AtomicBool = AtomicBool::new(false);

// =============================================================================
// HID Keycode to ASCII
// =============================================================================

const HID_ASCII: [u8; 64] = [
    0,0,0,0, b'a',b'b',b'c',b'd', b'e',b'f',b'g',b'h', b'i',b'j',b'k',b'l',
    b'm',b'n',b'o',b'p', b'q',b'r',b's',b't', b'u',b'v',b'w',b'x', b'y',b'z',b'1',b'2',
    b'3',b'4',b'5',b'6', b'7',b'8',b'9',b'0', 13,27,8,9, b' ',b'-',b'=',b'[',
    b']',b'\\',0,b';', b'\'',b'`',b',',b'.', b'/',0,0,0, 0,0,0,0,
];

const HID_ASCII_SHIFT: [u8; 64] = [
    0,0,0,0, b'A',b'B',b'C',b'D', b'E',b'F',b'G',b'H', b'I',b'J',b'K',b'L',
    b'M',b'N',b'O',b'P', b'Q',b'R',b'S',b'T', b'U',b'V',b'W',b'X', b'Y',b'Z',b'!',b'@',
    b'#',b'$',b'%',b'^', b'&',b'*',b'(',b')', 13,27,8,9, b' ',b'_',b'+',b'{',
    b'}',b'|',0,b':', b'"',b'~',b'<',b'>', b'?',0,0,0, 0,0,0,0,
];

// =============================================================================
// HID Report Processing
// =============================================================================

pub fn process_keyboard_report() -> Option<u8> {
    // SAFETY: Single-threaded HID processing, no concurrent access to HID_REPORTS/PREV_KEYS/KEY_QUEUE
    unsafe {
        let hid_reports_ptr = addr_of_mut!(HID_REPORTS);
        let report = &(*hid_reports_ptr).kbd;
        let modifiers = report[0];
        KEY_MOD.store(modifiers, Ordering::Relaxed);

        let prev_keys_ptr = addr_of_mut!(PREV_KEYS);

        // Keys are in bytes 2-7
        for i in 2..8 {
            let key = report[i];
            if key != 0 {
                // Check if this is a new key
                let mut is_new = true;
                for &prev in (*prev_keys_ptr).iter() {
                    if prev == key { is_new = false; break; }
                }

                if is_new {
                    if let Some(ascii) = hid_to_ascii(key, modifiers) {
                        // Add to queue
                        let tail = KEY_QUEUE_TAIL.load(Ordering::Relaxed);
                        let next = (tail + 1) & 0x0F;
                        if next != KEY_QUEUE_HEAD.load(Ordering::Relaxed) {
                            let key_queue_ptr = addr_of_mut!(KEY_QUEUE);
                            (*key_queue_ptr)[tail as usize] = ascii;
                            KEY_QUEUE_TAIL.store(next, Ordering::SeqCst);
                        }
                    }
                }
            }
        }

        // Update prev keys
        (*prev_keys_ptr).copy_from_slice(&report[2..8]);
    }

    // Return key from queue
    let head = KEY_QUEUE_HEAD.load(Ordering::Relaxed);
    let tail = KEY_QUEUE_TAIL.load(Ordering::Relaxed);
    if head != tail {
        // SAFETY: Single-threaded HID processing, no concurrent access to KEY_QUEUE
        let key = unsafe {
            let key_queue_ptr = addr_of_mut!(KEY_QUEUE);
            (*key_queue_ptr)[head as usize]
        };
        KEY_QUEUE_HEAD.store((head + 1) & 0x0F, Ordering::SeqCst);
        Some(key)
    } else {
        None
    }
}

pub fn process_mouse_report() {
    // SAFETY: Single-threaded HID processing, no concurrent access to HID_REPORTS
    unsafe {
        let hid_reports_ptr = addr_of_mut!(HID_REPORTS);
        let report = &(*hid_reports_ptr).mouse;
        let buttons = report[0];
        let dx = report[1] as i8 as i32;
        let dy = report[2] as i8 as i32;

        MOUSE_BTN.store(buttons, Ordering::Relaxed);

        let x = MOUSE_X.load(Ordering::Relaxed);
        let y = MOUSE_Y.load(Ordering::Relaxed);
        let w = SCR_W.load(Ordering::Relaxed);
        let h = SCR_H.load(Ordering::Relaxed);

        let nx = (x + dx).clamp(0, w - 1);
        let ny = (y + dy).clamp(0, h - 1);

        MOUSE_X.store(nx, Ordering::Relaxed);
        MOUSE_Y.store(ny, Ordering::Relaxed);
    }
}

pub fn hid_to_ascii(code: u8, mods: u8) -> Option<u8> {
    if code as usize >= HID_ASCII.len() { return None; }
    let shift = (mods & 0x22) != 0; // Left or right shift
    let ch = if shift { HID_ASCII_SHIFT[code as usize] } else { HID_ASCII[code as usize] };
    if ch != 0 { Some(ch) } else { None }
}

pub fn start_hid_poll() {
    if !HID_POLL_PENDING.load(Ordering::Relaxed) {
        // SAFETY: Single-threaded HID polling initialization, getting address for DMA
        let buf_p = unsafe {
            let hid_reports_ptr = addr_of_mut!(HID_REPORTS);
            (*hid_reports_ptr).kbd.as_ptr() as u64
        };
        let max_pkt = MAX_PACKET.load(Ordering::Relaxed) as u32;

        // Queue Normal TRB for interrupt transfer
        queue_hid((buf_p & 0xFFFFFFFF) as u32, (buf_p >> 32) as u32,
                  max_pkt, (TRB_TYPE_NORMAL << 10) | TRB_IOC | TRB_ISP);

        // Ring doorbell
        let slot = SLOT_ID.load(Ordering::Relaxed);
        let dci = HID_EP_DCI.load(Ordering::Relaxed);
        ring_db(slot, dci);

        HID_POLL_PENDING.store(true, Ordering::SeqCst);
    }
}
