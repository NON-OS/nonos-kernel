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

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use crate::sys::serial;
use super::structures::USB_BUF;
use crate::input::usb_hid::ring::wait_event;
use crate::input::usb_hid::transfer::{USB_DESC_INTERFACE, EpInfo};
use crate::input::usb_hid::hid::start_hid_poll;
use crate::input::usb_hid::{KBD_AVAIL, MOUSE_AVAIL};

pub(super) fn process_configure_result(_slot: u8, ep_info: &EpInfo) -> bool {
    if let Some((33, code, _)) = wait_event(100_000) {
        if code != 1 {
            serial::print(b"[USB] CfgEP fail ");
            serial::print_dec(code as u64);
            serial::println(b"");
            return false;
        }
        serial::println(b"[USB] Endpoint configured");
        let proto = unsafe {
            let usb_buf_ptr = addr_of_mut!(USB_BUF);
            (*usb_buf_ptr).data.iter().position(|&x| x == USB_DESC_INTERFACE)
                .map(|i| (*usb_buf_ptr).data.get(i + 7).copied().unwrap_or(0)).unwrap_or(0)
        };
        if proto == 1 || ep_info.max_packet <= 8 {
            KBD_AVAIL.store(true, Ordering::SeqCst);
            serial::println(b"[USB] Keyboard ready");
        }
        if proto == 2 || (proto == 0 && ep_info.max_packet <= 8) {
            MOUSE_AVAIL.store(true, Ordering::SeqCst);
            serial::println(b"[USB] Mouse ready");
        }
        start_hid_poll();
        return true;
    }
    false
}
