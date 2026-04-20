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
use super::consts::TRB_TYPE_CONFIGURE_ENDPOINT;
use super::structures::{DEV_CTX, INPUT_CTX, USB_BUF};
use super::state::{HID_EP_ADDR, HID_EP_DCI, HID_INTERVAL};
use crate::input::usb_hid::ring::{HID_EP_RING, queue_cmd};
use crate::input::usb_hid::transfer::{get_descriptor, set_configuration, set_protocol, set_idle};
use crate::input::usb_hid::transfer::{parse_config_descriptor, USB_DESC_CONFIGURATION};
use super::result::process_configure_result;

pub(super) fn get_descriptors_and_configure(slot: u8) -> bool {
    unsafe { for i in 0..64 { USB_BUF.data[i] = 0; } }
    let _ = get_descriptor(slot, crate::input::usb_hid::transfer::USB_DESC_DEVICE, 0, 8);
    unsafe { for i in 0..256 { USB_BUF.data[i] = 0; } }
    if !get_descriptor(slot, USB_DESC_CONFIGURATION, 0, 9) {
        serial::println(b"[USB] GetCfgDesc fail");
        return false;
    }
    let total_len = unsafe { (USB_BUF.data[2] as u16) | ((USB_BUF.data[3] as u16) << 8) };
    serial::print(b"[USB] Cfg len ");
    serial::print_dec(total_len as u64);
    serial::println(b"");
    unsafe { for i in 0..256 { USB_BUF.data[i] = 0; } }
    if !get_descriptor(slot, USB_DESC_CONFIGURATION, 0, total_len.min(255)) {
        serial::println(b"[USB] GetCfgDesc full fail");
        return false;
    }
    if let Some((cfg_val, iface, ep_info)) = parse_config_descriptor() {
        return configure_endpoint(slot, cfg_val, iface, ep_info);
    }
    serial::println(b"[USB] No HID endpoint");
    false
}

fn configure_endpoint(slot: u8, cfg_val: u8, iface: u8, ep_info: crate::input::usb_hid::transfer::EpInfo) -> bool {
    if !set_configuration(slot, cfg_val) { serial::println(b"[USB] SetCfg fail"); }
    serial::println(b"[USB] Configuration set");
    // Only set boot protocol for boot-class devices (not tablets)
    if !crate::input::usb_hid::TABLET_MODE.load(core::sync::atomic::Ordering::Relaxed) {
        if !set_protocol(slot, iface, 0) { serial::println(b"[USB] SetProto fail"); }
    }
    set_idle(slot, iface);
    let ep_num = ep_info.address & 0x0F;
    let ep_dci = ep_num * 2 + 1;
    HID_EP_ADDR.store(ep_info.address, Ordering::SeqCst);
    HID_EP_DCI.store(ep_dci, Ordering::SeqCst);
    HID_INTERVAL.store(ep_info.interval, Ordering::SeqCst);
    unsafe { setup_input_ctx_configure(slot, ep_dci, &ep_info); }
    let inp_p = addr_of_mut!(INPUT_CTX) as u64;
    core::sync::atomic::fence(Ordering::SeqCst);
    queue_cmd((inp_p & 0xFFFFFFFF) as u32, (inp_p >> 32) as u32, 0,
              (TRB_TYPE_CONFIGURE_ENDPOINT << 10) | ((slot as u32) << 24));
    process_configure_result(slot, &ep_info)
}

unsafe fn setup_input_ctx_configure(_slot: u8, ep_dci: u8, ep_info: &crate::input::usb_hid::transfer::EpInfo) {
    let input_ctx_ptr = addr_of_mut!(INPUT_CTX);
    // Zero everything with volatile writes
    for i in 0..8 { core::ptr::write_volatile(&mut (*input_ctx_ptr).ctrl[i], 0); core::ptr::write_volatile(&mut (*input_ctx_ptr).slot[i], 0); }
    for i in 0..31 { for j in 0..8 { core::ptr::write_volatile(&mut (*input_ctx_ptr).ep[i][j], 0); } }
    // Add flags: A0 (Slot Context) + endpoint DCI
    core::ptr::write_volatile(&mut (*input_ctx_ptr).ctrl[1], (1u32 << (ep_dci as u32)) | 1);
    let dev_ctx_ptr = addr_of_mut!(DEV_CTX);
    for i in 0..8 { core::ptr::write_volatile(&mut (*input_ctx_ptr).slot[i], core::ptr::read_volatile(&(*dev_ctx_ptr).slot[i])); }
    let ctx_entries = ep_dci.max(1);
    let slot0 = core::ptr::read_volatile(&(*input_ctx_ptr).slot[0]);
    core::ptr::write_volatile(&mut (*input_ctx_ptr).slot[0], (slot0 & 0x07FFFFFF) | ((ctx_entries as u32) << 27));
    let ep_idx = (ep_dci - 1) as usize;
    let hid_p = addr_of_mut!(HID_EP_RING) as u64;
    let interval_exp = ep_info.interval.saturating_sub(1).min(15);
    core::ptr::write_volatile(&mut (*input_ctx_ptr).ep[ep_idx][0], (interval_exp as u32) << 16);
    core::ptr::write_volatile(&mut (*input_ctx_ptr).ep[ep_idx][1], (3 << 1) | (7 << 3) | ((ep_info.max_packet as u32) << 16));
    core::ptr::write_volatile(&mut (*input_ctx_ptr).ep[ep_idx][2], (hid_p & 0xFFFFFFFF) as u32 | 1);
    core::ptr::write_volatile(&mut (*input_ctx_ptr).ep[ep_idx][3], (hid_p >> 32) as u32);
    core::ptr::write_volatile(&mut (*input_ctx_ptr).ep[ep_idx][4], ep_info.max_packet as u32);
}
