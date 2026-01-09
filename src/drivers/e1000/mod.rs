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

//! Intel E1000 Ethernet driver.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

mod constants;
mod descriptors;
mod device;
pub mod error;
mod interface;
#[cfg(test)]
mod tests;

pub use constants::*;
pub use descriptors::{E1000RxDesc, E1000TxDesc};
pub use device::E1000Device;
pub use interface::{register_with_network_stack, E1000SmolBridge, E1000Stats, E1000_SMOL_BRIDGE};

static E1000_DEVICE: spin::Once<Arc<Mutex<E1000Device>>> = spin::Once::new();
static E1000_PRESENT: AtomicBool = AtomicBool::new(false);

pub fn init_e1000() -> Result<(), &'static str> {
    let devices = crate::drivers::pci::scan_and_collect();

    for dev in devices {
        if dev.vendor_id() == INTEL_VENDOR_ID && E1000_DEVICE_IDS.contains(&dev.device_id_value()) {
            crate::log::info!(
                "e1000: Found Intel NIC {:04x}:{:04x} at {:02x}:{:02x}.{}",
                dev.vendor_id(),
                dev.device_id_value(),
                dev.bus(),
                dev.device(),
                dev.function()
            );

            let e1000_dev = E1000Device::new(dev)?;
            let arc = Arc::new(Mutex::new(e1000_dev));
            E1000_DEVICE.call_once(|| arc.clone());
            E1000_PRESENT.store(true, Ordering::SeqCst);

            register_with_network_stack();

            return Ok(());
        }
    }

    Err("e1000: No compatible device found")
}

pub fn get_e1000_device() -> Option<Arc<Mutex<E1000Device>>> {
    E1000_DEVICE.get().cloned()
}

pub fn is_present() -> bool {
    E1000_PRESENT.load(Ordering::Relaxed)
}

pub fn get_stats() -> Option<E1000Stats> {
    E1000Stats::from_device()
}

pub fn handle_interrupt() {
    if let Some(dev) = get_e1000_device() {
        dev.lock().handle_interrupt();
    }
}

pub fn reclaim_tx() {
    if let Some(dev) = get_e1000_device() {
        dev.lock().reclaim_tx();
    }
}

pub fn get_link_status() -> Option<(bool, u16, bool)> {
    let dev = get_e1000_device()?;
    let guard = dev.lock();
    Some((guard.link_up, guard.link_speed, guard.full_duplex))
}

pub fn get_mac_address() -> Option<[u8; 6]> {
    let dev = get_e1000_device()?;
    let guard = dev.lock();
    Some(guard.mac_address)
}
