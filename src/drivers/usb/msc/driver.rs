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

use alloc::sync::Arc;
use spin::Mutex;
use crate::drivers::usb::device::UsbDevice;
use crate::drivers::usb::descriptors::{UsbConfiguration, UsbInterfaceInfo};
use crate::drivers::usb::class_driver::UsbClassDriver;
use crate::drivers::usb::constants::*;
use super::state::MscDeviceState;
use super::registry::register_msc_device;
use super::commands::{test_unit_ready, request_sense, inquiry, get_capacity};

pub struct MscClassDriver;

impl UsbClassDriver for MscClassDriver {
    fn matches(&self, _dev: &UsbDevice, _cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> bool {
        iface.iface.b_interface_class == CLASS_MASS_STORAGE &&
        iface.iface.b_interface_sub_class == 0x06 &&
        iface.iface.b_interface_protocol == 0x50
    }

    fn bind(&self, dev: &UsbDevice, _cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> Result<(), &'static str> {
        let mut bulk_in = None;
        let mut bulk_out = None;

        for ep in &iface.endpoints {
            if ep.is_bulk() {
                if ep.is_in() {
                    bulk_in = Some(ep.b_endpoint_address & 0x0F);
                } else {
                    bulk_out = Some(ep.b_endpoint_address & 0x0F);
                }
            }
        }

        let bulk_in_ep = bulk_in.ok_or("No bulk IN endpoint")?;
        let bulk_out_ep = bulk_out.ok_or("No bulk OUT endpoint")?;

        let mut state = MscDeviceState::new(dev.slot_id, bulk_in_ep, bulk_out_ep);

        let mut ready = false;
        for _ in 0..10 {
            if test_unit_ready(&state).unwrap_or(false) {
                ready = true;
                break;
            }
            let _ = request_sense(&state);
            crate::time::sleep_ms(100);
        }

        if !ready {
            crate::log_warn!("[USB MSC] Device not ready after 10 attempts");
        }

        if let Ok(inq) = inquiry(&state) {
            crate::log_info!(
                "[USB MSC] Device: {} {} ({})",
                inq.vendor, inq.product, inq.revision
            );
            state.inquiry = Some(inq);
        }

        if let Ok(cap) = get_capacity(&state) {
            crate::log_info!(
                "[USB MSC] Capacity: {} blocks x {} bytes = {} MB",
                cap.total_blocks, cap.block_size, cap.total_mb()
            );
            state.capacity = Some(cap);
        }

        register_msc_device(dev.slot_id, Arc::new(Mutex::new(state)));

        Ok(())
    }

    fn unbind(&self, dev: &UsbDevice, _iface: &UsbInterfaceInfo) {
        super::registry::unregister_msc_device(dev.slot_id);
    }

    fn name(&self) -> &'static str {
        "MSC"
    }

    fn priority(&self) -> u8 {
        10
    }
}
