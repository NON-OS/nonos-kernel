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

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use core::sync::atomic::Ordering;

use super::super::backend::UsbHostBackend;
use super::super::constants::*;
use super::super::descriptors::*;
use super::super::device::UsbDevice;
use super::core::UsbManager;

impl<B: UsbHostBackend> UsbManager<B> {
    pub fn enumerate(&self) -> Result<(), &'static str> {
        crate::log::logger::log_critical("[USB] Starting device enumeration...");

        let slots = match self.backend.enumerate_all_devices() {
            Ok(s) => {
                crate::log::logger::log_critical(&alloc::format!("[USB] xHCI returned {} slot(s)", s.len()));
                s
            }
            Err(e) => {
                crate::log::logger::log_critical(&alloc::format!("[USB] xHCI enumerate failed: {}", e));
                return Err(e);
            }
        };

        if slots.is_empty() {
            crate::log::logger::log_critical("[USB] No USB devices found on any port");
            return Err("usb: no devices found");
        }

        for slot in &slots {
            crate::log::logger::log_critical(&alloc::format!("[USB] Processing slot {}", slot));
            match self.enumerate_slot(*slot) {
                Ok(()) => {
                    crate::log::logger::log_critical(&alloc::format!("[USB] Slot {} enumerated OK", slot));
                }
                Err(e) => {
                    crate::log::logger::log_critical(&alloc::format!("[USB] Slot {} failed: {}", slot, e));
                }
            }
        }

        let device_count = self.devices.lock().len();
        crate::log::logger::log_critical(&alloc::format!("[USB] Total devices: {}", device_count));

        if device_count == 0 {
            return Err("usb: failed to enumerate any devices");
        }

        Ok(())
    }

    pub(super) fn enumerate_slot(&self, slot: u8) -> Result<(), &'static str> {
        let mut buf = [0u8; 18];
        let setup_short = [
            DIR_IN | TYPE_STD | RT_DEV,
            REQ_GET_DESCRIPTOR,
            DT_DEVICE, 0,
            0, 0,
            8, 0,
        ];
        self.backend.control_transfer(slot, setup_short, Some(&mut buf[..8]), None, DEFAULT_CONTROL_TIMEOUT_US)?;

        let setup_full = [
            DIR_IN | TYPE_STD | RT_DEV,
            REQ_GET_DESCRIPTOR,
            DT_DEVICE, 0,
            0, 0,
            18, 0,
        ];
        let n = self.backend.control_transfer(slot, setup_full, Some(&mut buf), None, DEFAULT_CONTROL_TIMEOUT_US)?;
        if n < 18 {
            return Err("usb: short device descriptor");
        }
        let dev_desc: DeviceDescriptor = unsafe {
            core::ptr::read_unaligned(buf.as_ptr() as *const DeviceDescriptor)
        };

        let strings = self.fetch_strings(slot, &dev_desc)?;

        let mut cfg_hdr_buf = [0u8; core::mem::size_of::<ConfigDescriptorHeader>()];
        let setup_cfg_hdr = [
            DIR_IN | TYPE_STD | RT_DEV,
            REQ_GET_DESCRIPTOR,
            DT_CONFIG, 0,
            0, 0,
            cfg_hdr_buf.len() as u8, 0,
        ];
        let n = self.backend.control_transfer(slot, setup_cfg_hdr, Some(&mut cfg_hdr_buf), None, DEFAULT_CONTROL_TIMEOUT_US)?;
        if n < cfg_hdr_buf.len() {
            return Err("usb: short config header");
        }
        let cfg_hdr: ConfigDescriptorHeader = unsafe {
            core::ptr::read_unaligned(cfg_hdr_buf.as_ptr() as *const ConfigDescriptorHeader)
        };
        let total_len = u16::from_le(cfg_hdr.w_total_length) as usize;

        let mut cfg_buf = vec![0u8; total_len];
        let setup_cfg_full = [
            DIR_IN | TYPE_STD | RT_DEV,
            REQ_GET_DESCRIPTOR,
            DT_CONFIG, 0,
            0, 0,
            (total_len & 0xFF) as u8, (total_len >> 8) as u8,
        ];
        let n = self.backend.control_transfer(slot, setup_cfg_full, Some(&mut cfg_buf), None, DEFAULT_CONTROL_TIMEOUT_US)?;
        if n < total_len {
            return Err("usb: short config descriptor");
        }
        let cfg_hdr_full: ConfigDescriptorHeader = unsafe {
            core::ptr::read_unaligned(cfg_buf.as_ptr() as *const ConfigDescriptorHeader)
        };

        let interfaces = parse_interfaces(&cfg_buf)?;

        let cfg_value = cfg_hdr_full.b_configuration_value;
        let setup_set_cfg = [
            DIR_OUT | TYPE_STD | RT_DEV,
            REQ_SET_CONFIGURATION,
            cfg_value, 0,
            0, 0,
            0, 0,
        ];
        self.backend.control_transfer(slot, setup_set_cfg, None, None, DEFAULT_CONTROL_TIMEOUT_US)?;

        let device = UsbDevice {
            slot_id: slot,
            addr: 0,
            dev_desc,
            strings,
            active_config: Some(UsbConfiguration {
                header: cfg_hdr_full,
                raw: cfg_buf,
                interfaces,
            }),
        };

        self.devices.lock().push(device);
        self.stats.devices_enumerated.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn fetch_strings(&self, slot: u8, dd: &DeviceDescriptor) -> Result<UsbStringTable, &'static str> {
        let mut out = UsbStringTable::new();

        if dd.i_manufacturer != 0 {
            out.manufacturer = self.get_string(slot, dd.i_manufacturer).ok();
        }
        if dd.i_product != 0 {
            out.product = self.get_string(slot, dd.i_product).ok();
        }
        if dd.i_serial_number != 0 {
            out.serial = self.get_string(slot, dd.i_serial_number).ok();
        }

        Ok(out)
    }

    pub fn get_string(&self, slot: u8, index: u8) -> Result<String, &'static str> {
        let langid = DEFAULT_LANG_ID;
        let mut buf = [0u8; 255];
        let setup = [
            DIR_IN | TYPE_STD | RT_DEV,
            REQ_GET_DESCRIPTOR,
            DT_STRING, index,
            (langid & 0xFF) as u8, (langid >> 8) as u8,
            255, 0,
        ];

        let n = self.backend.control_transfer(slot, setup, Some(&mut buf), None, DEFAULT_CONTROL_TIMEOUT_US)?;
        if n < 2 || buf[1] != DT_STRING {
            return Err("usb: invalid string descriptor");
        }

        let mut s = String::new();
        let mut i = 2usize;
        while i + 1 < n {
            let lo = buf[i];
            let hi = buf[i + 1];
            let cp = u16::from_le_bytes([lo, hi]);
            let ch = core::char::from_u32(cp as u32).unwrap_or('?');
            s.push(ch);
            i += 2;
        }
        Ok(s)
    }

    pub fn get_string_descriptor(&self, slot_id: u8, index: u8) -> Result<String, &'static str> {
        self.get_string(slot_id, index)
    }
}
