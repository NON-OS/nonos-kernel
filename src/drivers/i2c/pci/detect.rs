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

use alloc::vec::Vec;

use super::constants::KNOWN_TOUCHPAD_ADDRS;
use super::init::scan_bus;

pub fn detect_hid_devices() -> Vec<(usize, u8)> {
    let mut hid_devices = Vec::new();

    let count = super::super::controller_count();
    crate::log::info!("i2c: Scanning {} controller(s) for HID devices", count);

    for ctrl_idx in 0..count {
        for &addr in KNOWN_TOUCHPAD_ADDRS {
            if let Some(ctrl) = super::super::get_controller(ctrl_idx) {
                if ctrl.probe(addr) {
                    crate::log::info!("i2c: Found device at bus {} addr 0x{:02x}", ctrl_idx, addr);
                    if is_hid_device(ctrl_idx, addr) {
                        hid_devices.push((ctrl_idx, addr));
                        crate::log::info!(
                            "i2c: Confirmed HID at bus {} addr 0x{:02x}",
                            ctrl_idx,
                            addr
                        );
                    } else if is_hid_device_relaxed(ctrl_idx, addr) {
                        hid_devices.push((ctrl_idx, addr));
                        crate::log::info!(
                            "i2c: HID (relaxed) at bus {} addr 0x{:02x}",
                            ctrl_idx,
                            addr
                        );
                    }
                }
            }
        }

        let addresses = scan_bus(ctrl_idx);
        for addr in addresses {
            if hid_devices
                .iter()
                .any(|(c, a)| *c == ctrl_idx && *a == addr)
            {
                continue;
            }
            if is_hid_device(ctrl_idx, addr) {
                hid_devices.push((ctrl_idx, addr));
                crate::log::info!(
                    "i2c: Found HID device at bus {} addr 0x{:02x}",
                    ctrl_idx,
                    addr
                );
            }
        }
    }

    if hid_devices.is_empty() {
        crate::log::info!("i2c: No HID devices found on {} controllers", count);
    }

    hid_devices
}

fn is_hid_device(controller: usize, addr: u8) -> bool {
    let ctrl = match super::super::get_controller(controller) {
        Some(c) => c,
        None => return false,
    };

    let mut desc_addr = [0u8; 2];
    if ctrl
        .write_read(addr, &[0x01, 0x00], &mut desc_addr)
        .is_err()
    {
        return false;
    }

    let mut hid_desc = [0u8; 30];
    if ctrl
        .write_read(addr, &[0x01, 0x00], &mut hid_desc)
        .is_err()
    {
        return false;
    }

    let desc_len = u16::from_le_bytes([hid_desc[0], hid_desc[1]]);
    if desc_len < 30 || desc_len > 256 {
        return false;
    }

    let bcd_version = u16::from_le_bytes([hid_desc[2], hid_desc[3]]);
    if bcd_version != 0x0100 {
        return false;
    }

    true
}

fn is_hid_device_relaxed(controller: usize, addr: u8) -> bool {
    let ctrl = match super::super::get_controller(controller) {
        Some(c) => c,
        None => return false,
    };

    let mut hid_desc = [0u8; 30];
    if ctrl
        .write_read(addr, &[0x01, 0x00], &mut hid_desc)
        .is_ok()
    {
        let desc_len = u16::from_le_bytes([hid_desc[0], hid_desc[1]]);
        let bcd_version = u16::from_le_bytes([hid_desc[2], hid_desc[3]]);

        if desc_len >= 28 && desc_len <= 256 {
            if bcd_version >= 0x0100 && bcd_version <= 0x0111 {
                crate::log::info!(
                    "i2c: Relaxed HID match at 0x{:02x}: len={}, ver=0x{:04x}",
                    addr,
                    desc_len,
                    bcd_version
                );
                return true;
            }
        }

        if desc_len >= 20 {
            let report_desc_len = u16::from_le_bytes([hid_desc[4], hid_desc[5]]);
            let report_desc_reg = u16::from_le_bytes([hid_desc[6], hid_desc[7]]);
            if report_desc_len > 0 && report_desc_len < 4096 && report_desc_reg != 0 {
                crate::log::info!(
                    "i2c: ELAN-style HID at 0x{:02x}: rdesc_len={}, rdesc_reg=0x{:04x}",
                    addr,
                    report_desc_len,
                    report_desc_reg
                );
                return true;
            }
        }
    }

    for desc_reg in &[0x0020u16, 0x0021, 0x0030] {
        let reg_bytes = desc_reg.to_le_bytes();
        if ctrl.write_read(addr, &reg_bytes, &mut hid_desc).is_ok() {
            let desc_len = u16::from_le_bytes([hid_desc[0], hid_desc[1]]);
            if desc_len >= 28 && desc_len <= 256 {
                crate::log::info!(
                    "i2c: Alternate HID at 0x{:02x} reg 0x{:04x}: len={}",
                    addr,
                    desc_reg,
                    desc_len
                );
                return true;
            }
        }
    }

    false
}
