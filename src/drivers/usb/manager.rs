// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::backend::{UsbHostBackend, XhciBackend};
use super::constants::*;
use super::descriptors::*;
use super::device::UsbDevice;
use super::class_driver::bind_drivers_to_device;

#[derive(Default)]
pub struct UsbStats {
    pub devices_enumerated: AtomicU64,
    pub ctrl_transfers: AtomicU64,
    pub ctrl_errors: AtomicU64,
    pub bulk_transfers: AtomicU64,
    pub bulk_errors: AtomicU64,
    pub int_transfers: AtomicU64,
    pub int_errors: AtomicU64,
}

impl UsbStats {
    pub fn snapshot(&self) -> UsbStatsSnapshot {
        UsbStatsSnapshot {
            devices_enumerated: self.devices_enumerated.load(Ordering::Relaxed),
            ctrl_transfers: self.ctrl_transfers.load(Ordering::Relaxed),
            ctrl_errors: self.ctrl_errors.load(Ordering::Relaxed),
            bulk_transfers: self.bulk_transfers.load(Ordering::Relaxed),
            bulk_errors: self.bulk_errors.load(Ordering::Relaxed),
            int_transfers: self.int_transfers.load(Ordering::Relaxed),
            int_errors: self.int_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UsbStatsSnapshot {
    pub devices_enumerated: u64,
    pub ctrl_transfers: u64,
    pub ctrl_errors: u64,
    pub bulk_transfers: u64,
    pub bulk_errors: u64,
    pub int_transfers: u64,
    pub int_errors: u64,
}

pub struct UsbManager<B: UsbHostBackend> {
    backend: B,
    devices: Mutex<Vec<UsbDevice>>,
    stats: UsbStats,
}

impl<B: UsbHostBackend> UsbManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            devices: Mutex::new(Vec::new()),
            stats: UsbStats::default(),
        }
    }

    pub fn enumerate(&self) -> Result<(), &'static str> {
        let slot = self.backend.default_slot().ok_or("usb: no default slot")?;

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
        // SAFETY: buffer contains valid descriptor data, using read_unaligned for packed struct.
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
        // SAFETY: buffer contains valid descriptor data, using read_unaligned for packed struct.
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
        // SAFETY: buffer contains valid descriptor data, using read_unaligned for packed struct.
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

    fn get_string(&self, slot: u8, index: u8) -> Result<String, &'static str> {
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

    pub fn bind_class_drivers(&self) {
        let devs = self.devices.lock().clone();
        for dev in &devs {
            bind_drivers_to_device(dev);
        }
    }

    pub fn devices(&self) -> Vec<UsbDevice> {
        self.devices.lock().clone()
    }

    pub fn stats(&self) -> UsbStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn poll_endpoint(&self, device_id: u8, endpoint: u8, buffer: &mut [u8]) -> Result<usize, &'static str> {
        let devices = self.devices.lock();
        let device = devices.iter().find(|d| d.slot_id == device_id)
            .ok_or("Device not found")?;

        let config = device.active_config.as_ref()
            .ok_or("No active configuration")?;

        for interface in &config.interfaces {
            for ep_desc in &interface.endpoints {
                if ep_desc.b_endpoint_address == endpoint {
                    let transfer_type = ep_desc.transfer_type();
                    return match transfer_type {
                        EP_TYPE_ISOCHRONOUS => {
                            Err("Isochronous transfers not supported in polling")
                        }
                        EP_TYPE_BULK => {
                            self.stats.bulk_transfers.fetch_add(1, Ordering::Relaxed);
                            self.backend.bulk_transfer(
                                device.slot_id,
                                endpoint,
                                buffer,
                                DEFAULT_BULK_TIMEOUT_US,
                            ).map_err(|e| {
                                self.stats.bulk_errors.fetch_add(1, Ordering::Relaxed);
                                e
                            })
                        }
                        EP_TYPE_INTERRUPT => {
                            self.stats.int_transfers.fetch_add(1, Ordering::Relaxed);
                            self.backend.interrupt_transfer(
                                device.slot_id,
                                endpoint,
                                buffer,
                                ep_desc.b_interval,
                                DEFAULT_INTERRUPT_TIMEOUT_US,
                            ).map_err(|e| {
                                self.stats.int_errors.fetch_add(1, Ordering::Relaxed);
                                e
                            })
                        }
                        _ => {
                            Err("Control endpoints should use control_transfer")
                        }
                    };
                }
            }
        }

        Err("Endpoint not found in device configuration")
    }
}

static USB_MANAGER: spin::Once<&'static UsbManager<XhciBackend>> = spin::Once::new();
pub fn init_usb() -> Result<(), &'static str> {
    let mgr = USB_MANAGER.call_once(|| {
        let m = UsbManager::new(XhciBackend);
        Box::leak(Box::new(m))
    });

    mgr.enumerate()?;
    mgr.bind_class_drivers();
    crate::log::logger::log_critical("USB core initialized");
    Ok(())
}

pub fn get_manager() -> Option<&'static UsbManager<XhciBackend>> {
    USB_MANAGER.get().copied()
}

pub fn poll_endpoint(device_id: u8, endpoint: u8, buffer: &mut [u8]) -> Result<usize, &'static str> {
    get_manager()
        .ok_or("USB manager not initialized")?
        .poll_endpoint(device_id, endpoint, buffer)
}
