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

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

mod constants;
mod device;
pub mod error;
mod interface;
mod io;
#[cfg(test)]
mod tests;

pub use constants::*;
pub use device::Rtl8139Device;
pub use interface::{register_with_network_stack, Rtl8139SmolBridge, Rtl8139Stats, RTL8139_SMOL_BRIDGE};

static RTL8139_DEVICE: spin::Once<Arc<Mutex<Rtl8139Device>>> = spin::Once::new();
static RTL8139_PRESENT: AtomicBool = AtomicBool::new(false);

pub fn init_rtl8139() -> Result<(), &'static str> {
    let devices = crate::drivers::pci::scan_and_collect();

    for dev in devices {
        if dev.vendor_id() == REALTEK_VENDOR_ID
            && RTL8139_DEVICE_IDS.contains(&dev.device_id_value())
        {
            crate::log::info!(
                "rtl8139: Found Realtek NIC {:04x}:{:04x} at {:02x}:{:02x}.{}",
                dev.vendor_id(),
                dev.device_id_value(),
                dev.bus(),
                dev.device(),
                dev.function()
            );

            let rtl_dev = Rtl8139Device::new(dev)?;
            let arc = Arc::new(Mutex::new(rtl_dev));
            RTL8139_DEVICE.call_once(|| arc.clone());
            RTL8139_PRESENT.store(true, Ordering::SeqCst);

            register_with_network_stack();

            return Ok(());
        }
    }

    Err("rtl8139: No compatible device found")
}

pub fn get_rtl8139_device() -> Option<Arc<Mutex<Rtl8139Device>>> {
    RTL8139_DEVICE.get().cloned()
}

pub fn is_present() -> bool {
    RTL8139_PRESENT.load(Ordering::Relaxed)
}

pub fn get_stats() -> Option<Rtl8139Stats> {
    Rtl8139Stats::from_device()
}

pub fn handle_interrupt() {
    if let Some(dev) = get_rtl8139_device() {
        dev.lock().handle_interrupt();
    }
}

pub fn get_link_status() -> Option<(bool, u16)> {
    let dev = get_rtl8139_device()?;
    let guard = dev.lock();
    Some((guard.link_up, guard.link_speed))
}

pub fn get_mac_address() -> Option<[u8; 6]> {
    let dev = get_rtl8139_device()?;
    let guard = dev.lock();
    Some(guard.mac_address)
}
