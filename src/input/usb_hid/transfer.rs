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
use crate::sys::serial;
use super::ring::{queue_ep0, ring_db, wait_event};
use super::xhci::USB_BUF;


pub(crate) const TRB_TYPE_SETUP: u32 = 2;
pub(crate) const TRB_TYPE_DATA: u32 = 3;
pub(crate) const TRB_TYPE_STATUS: u32 = 4;

pub(crate) const TRB_IOC: u32 = 1 << 5;
pub(crate) const TRB_IDT: u32 = 1 << 6;

pub(crate) const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub(crate) const USB_REQ_SET_CONFIGURATION: u8 = 0x09;

pub(crate) const USB_HID_REQ_SET_PROTOCOL: u8 = 0x0B;
pub(crate) const USB_HID_REQ_SET_IDLE: u8 = 0x0A;

pub(crate) const USB_DESC_DEVICE: u8 = 0x01;
pub(crate) const USB_DESC_CONFIGURATION: u8 = 0x02;
pub(crate) const USB_DESC_INTERFACE: u8 = 0x04;
pub(crate) const USB_DESC_ENDPOINT: u8 = 0x05;

pub(crate) const USB_CLASS_HID: u8 = 0x03;


pub(super) struct EndpointInfo {
    pub(super) address: u8,
    pub(super) attributes: u8,
    pub(super) max_packet: u16,
    pub(super) interval: u8,
}

impl EndpointInfo {
    pub(super) fn is_interrupt(&self) -> bool {
        (self.attributes & 0x03) == 0x03
    }
}


pub(crate) fn control_transfer(slot: u8, req_type: u8, req: u8, value: u16, index: u16,
                        data_ptr: u64, data_len: u16, dir_in: bool) -> bool {
    let setup0 = (req_type as u32) | ((req as u32) << 8) | ((value as u32) << 16);
    let setup1 = (index as u32) | ((data_len as u32) << 16);
    let setup2 = 8; // TRB transfer length = 8 (setup packet)
    let trt = if data_len == 0 { 0 } else if dir_in { 3 } else { 2 }; // No Data / IN / OUT
    let setup3 = (TRB_TYPE_SETUP << 10) | TRB_IDT | (trt << 16);
    queue_ep0(setup0, setup1, setup2, setup3);

    if data_len > 0 {
        let data0 = (data_ptr & 0xFFFFFFFF) as u32;
        let data1 = (data_ptr >> 32) as u32;
        let data2 = data_len as u32;
        let dir_bit = if dir_in { 1u32 << 16 } else { 0 };
        let data3 = (TRB_TYPE_DATA << 10) | dir_bit | TRB_IOC;
        queue_ep0(data0, data1, data2, data3);
    }

    let status_dir = if data_len > 0 && dir_in { 0 } else { 1u32 << 16 };
    let status3 = (TRB_TYPE_STATUS << 10) | status_dir | TRB_IOC;
    queue_ep0(0, 0, 0, status3);

    ring_db(slot, 1);

    for _ in 0..3 {
        if let Some((typ, code, _)) = wait_event(100_000) {
            if typ == 32 { // Transfer Event
                if code == 1 || code == 13 { // Success or Short Packet
                    continue; // Wait for more events
                }
            }
            if typ == 32 && (code == 1 || code == 13) {
                return true;
            }
        }
    }

    if let Some((_, code, _)) = wait_event(10_000) {
        return code == 1 || code == 13;
    }
    false
}

pub(crate) fn get_descriptor(slot: u8, desc_type: u8, desc_idx: u8, len: u16) -> bool {
    // SAFETY: Single-threaded USB transfer, no concurrent access to USB_BUF
    let data_ptr = unsafe {
        let usb_buf_ptr = addr_of_mut!(USB_BUF);
        (*usb_buf_ptr).data.as_ptr() as u64
    };
    control_transfer(slot, 0x80, USB_REQ_GET_DESCRIPTOR,
                     ((desc_type as u16) << 8) | (desc_idx as u16),
                     0, data_ptr, len, true)
}

pub(crate) fn set_configuration(slot: u8, config: u8) -> bool {
    control_transfer(slot, 0x00, USB_REQ_SET_CONFIGURATION, config as u16, 0, 0, 0, false)
}

pub(crate) fn set_protocol(slot: u8, interface: u8, protocol: u8) -> bool {
    control_transfer(slot, 0x21, USB_HID_REQ_SET_PROTOCOL, protocol as u16, interface as u16, 0, 0, false)
}

pub(crate) fn set_idle(slot: u8, interface: u8) -> bool {
    control_transfer(slot, 0x21, USB_HID_REQ_SET_IDLE, 0, interface as u16, 0, 0, false)
}


pub(super) fn parse_config_descriptor() -> Option<(u8, u8, EndpointInfo)> {
        // SAFETY: Single-threaded descriptor parsing, no concurrent access to USB_BUF
    unsafe {
        let usb_buf_ptr = addr_of_mut!(USB_BUF);
        let data = &(*usb_buf_ptr).data;
        if data[1] != USB_DESC_CONFIGURATION { return None; }

        let total_len = (data[2] as u16) | ((data[3] as u16) << 8);
        let config_val = data[5];

        let mut pos = 0usize;
        let mut cur_iface = 0u8;
        let mut found_hid = false;

        while pos < (total_len as usize).min(256) {
            let len = data[pos] as usize;
            if len < 2 { break; }
            let desc_type = data[pos + 1];

            match desc_type {
                USB_DESC_INTERFACE => {
                    if len >= 9 {
                        cur_iface = data[pos + 2];
                        let iface_class = data[pos + 5];
                        let iface_subclass = data[pos + 6];
                        let iface_protocol = data[pos + 7];

                        if iface_class == USB_CLASS_HID && iface_subclass == 1 {
                            found_hid = true;
                            serial::print(b"[USB] HID interface ");
                            serial::print_dec(cur_iface as u64);
                            serial::print(b" proto ");
                            serial::print_dec(iface_protocol as u64);
                            serial::println(b"");
                        }
                    }
                }
                USB_DESC_ENDPOINT => {
                    if len >= 7 && found_hid {
                        let ep_addr = data[pos + 2];
                        let ep_attr = data[pos + 3];
                        let ep_max = (data[pos + 4] as u16) | ((data[pos + 5] as u16) << 8);
                        let ep_interval = data[pos + 6];

                        let ep_info = EndpointInfo {
                            address: ep_addr,
                            attributes: ep_attr,
                            max_packet: ep_max,
                            interval: ep_interval,
                        };

                        if (ep_addr & 0x80) != 0 && ep_info.is_interrupt() {
                            serial::print(b"[USB] Int EP 0x");
                            serial::print_hex(ep_addr as u64);
                            serial::print(b" max ");
                            serial::print_dec(ep_max as u64);
                            serial::print(b" attr 0x");
                            serial::print_hex(ep_info.attributes as u64);
                            serial::println(b"");

                            return Some((config_val, cur_iface, ep_info));
                        }
                    }
                }
                _ => {}
            }

            pos += len;
        }
    }
    None
}
