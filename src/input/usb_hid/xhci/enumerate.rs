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
use super::consts::*;
use super::structures::{DCBAA, DEV_CTX, INPUT_CTX, USB_BUF};
use super::state::{SLOT_ID, MAX_PACKET, HID_EP_ADDR, HID_EP_DCI, HID_INTERVAL};
use crate::input::usb_hid::ring::{EP0_RING, HID_EP_RING, EVENT_RING, EVT_RING_IDX, queue_cmd, wait_event};
use crate::input::usb_hid::transfer::{get_descriptor, set_configuration, set_protocol, set_idle};
use crate::input::usb_hid::transfer::{parse_config_descriptor, USB_DESC_DEVICE, USB_DESC_CONFIGURATION};
use crate::input::usb_hid::transfer::USB_DESC_INTERFACE;
use super::address::setup_input_ctx_address;
use super::configure::get_descriptors_and_configure;

pub(super) fn enumerate_device(port: u8, speed: u8) -> bool {
    serial::print(b"[USB] Enum port ");
    serial::print_dec(port as u64);
    serial::println(b"");
    queue_cmd(0, 0, 0, TRB_TYPE_ENABLE_SLOT << 10);
    let slot = match get_slot_id() {
        Some(s) => s,
        None => return false,
    };
    if slot == 0 || slot > 16 {
        serial::println(b"[USB] Bad slot");
        return false;
    }
    serial::print(b"[USB] Slot ");
    serial::print_dec(slot as u64);
    serial::println(b"");
    SLOT_ID.store(slot, Ordering::SeqCst);
    if !address_device(slot, port, speed) { return false; }
    serial::println(b"[USB] Device addressed");
    get_descriptors_and_configure(slot)
}

fn get_slot_id() -> Option<u8> {
    if let Some((33, code, _)) = wait_event(100_000) {
        if code != 1 {
            serial::println(b"[USB] EnableSlot fail");
            return None;
        }
        let ei = EVT_RING_IDX.load(Ordering::Relaxed);
        let pi = if ei == 0 { 255 } else { ei - 1 } as usize;
        Some(unsafe { ((EVENT_RING.trbs[pi][3] >> 24) & 0xFF) as u8 })
    } else {
        serial::println(b"[USB] EnableSlot timeout");
        None
    }
}

fn address_device(slot: u8, port: u8, speed: u8) -> bool {
    let max_pkt = match speed { 1 => 8, 2 => 8, 3 => 64, 4 | 5 => 512, _ => 8 };
    MAX_PACKET.store(max_pkt as u8, Ordering::SeqCst);
    unsafe { setup_input_ctx_address(slot, port, speed, max_pkt); }
    let inp_p = addr_of_mut!(INPUT_CTX) as u64;
    queue_cmd((inp_p & 0xFFFFFFFF) as u32, (inp_p >> 32) as u32, 0,
              (TRB_TYPE_ADDRESS_DEVICE << 10) | ((slot as u32) << 24));
    if let Some((33, code, _)) = wait_event(100_000) {
        if code != 1 {
            serial::print(b"[USB] Addr fail ");
            serial::print_dec(code as u64);
            serial::println(b"");
            return false;
        }
    } else {
        serial::println(b"[USB] Addr timeout");
        return false;
    }
    true
}
