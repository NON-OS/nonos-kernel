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

use alloc::boxed::Box;

use super::super::backend::XhciBackend;
use super::core::UsbManager;

static USB_MANAGER: spin::Once<&'static UsbManager<XhciBackend>> = spin::Once::new();

pub fn init_usb() -> Result<(), &'static str> {
    let mgr = USB_MANAGER.call_once(|| {
        let m = UsbManager::new(XhciBackend);
        Box::leak(Box::new(m))
    });

    crate::drivers::usb::msc::init_msc_driver();
    crate::drivers::usb::cdc_eth::init();
    crate::drivers::usb::rtl8152::init();

    mgr.enumerate()?;

    let devices = mgr.devices();
    crate::log_info!("[USB] Enumerated {} device(s)", devices.len());
    for dev in &devices {
        crate::log_info!(
            "[USB] Device slot {}: VID={:04x} PID={:04x} class={:02x}",
            dev.slot_id,
            dev.vendor_id(),
            dev.product_id(),
            dev.device_class()
        );
    }

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
