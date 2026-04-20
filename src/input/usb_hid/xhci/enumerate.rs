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
use super::structures::INPUT_CTX;
use super::state::{SLOT_ID, MAX_PACKET};
use crate::input::usb_hid::ring::{queue_cmd, wait_event};
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
    // Drain pending events (e.g. Port Status Change type 34) until Command Completion
    for _ in 0..20 {
        if let Some((typ, cc, t3)) = wait_event(500_000) {
            if typ == 33 {
                if cc != 1 {
                    serial::print(b"[USB] EnableSlot fail cc=");
                    serial::print_dec(cc as u64);
                    serial::println(b"");
                    return None;
                }
                let slot = ((t3 >> 24) & 0xFF) as u8;
                return Some(slot);
            }
            // Skip non-command-completion event
            serial::print(b"[USB] Skip evt type ");
            serial::print_dec(typ as u64);
            serial::println(b"");
            continue;
        } else {
            break;
        }
    }
    serial::println(b"[USB] EnableSlot timeout");
    None
}

fn address_device(slot: u8, port: u8, speed: u8) -> bool {
    let max_pkt = match speed { 1 => 8, 2 => 8, 3 => 64, 4 | 5 => 512, _ => 8 };
    MAX_PACKET.store(max_pkt as u8, Ordering::SeqCst);
    unsafe { setup_input_ctx_address(slot, port, speed, max_pkt); }
    let inp_p = addr_of_mut!(INPUT_CTX) as u64;
    queue_cmd((inp_p & 0xFFFFFFFF) as u32, (inp_p >> 32) as u32, 0,
              (TRB_TYPE_ADDRESS_DEVICE << 10) | ((slot as u32) << 24));
    // Drain pending events until Command Completion
    for _ in 0..20 {
        if let Some((typ, cc, _)) = wait_event(500_000) {
            if typ == 33 {
                if cc != 1 {
                    serial::print(b"[USB] Addr fail cc=");
                    serial::print_dec(cc as u64);
                    serial::println(b"");
                    return false;
                }
                return true;
            }
            // Skip non-command-completion event
            continue;
        } else {
            break;
        }
    }
    serial::println(b"[USB] Addr timeout");
    false
}
