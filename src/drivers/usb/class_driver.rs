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
use alloc::vec::Vec;
use spin::Mutex;

use super::device::UsbDevice;
use super::descriptors::{UsbConfiguration, UsbInterfaceInfo};

pub trait UsbClassDriver: Send + Sync + 'static {
    fn matches(&self, dev: &UsbDevice, cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> bool;
    fn bind(&self, dev: &UsbDevice, cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> Result<(), &'static str>;
    fn name(&self) -> &'static str;
    fn unbind(&self, _dev: &UsbDevice, _iface: &UsbInterfaceInfo) {}
    fn priority(&self) -> u8 {
        0
    }
}

static CLASS_DRIVERS: Mutex<Vec<Arc<dyn UsbClassDriver>>> = Mutex::new(Vec::new());

pub fn register_class_driver(driver: Arc<dyn UsbClassDriver>) {
    let mut drivers = CLASS_DRIVERS.lock();
    let priority = driver.priority();
    let pos = drivers.iter().position(|d| d.priority() < priority)
        .unwrap_or(drivers.len());
    drivers.insert(pos, driver);
}

pub fn unregister_class_driver(name: &str) {
    let mut drivers = CLASS_DRIVERS.lock();
    drivers.retain(|d| d.name() != name);
}

pub fn get_class_drivers() -> Vec<Arc<dyn UsbClassDriver>> {
    CLASS_DRIVERS.lock().clone()
}

pub fn bind_drivers_to_device(dev: &UsbDevice) {
    let drivers = get_class_drivers();
    if let Some(cfg) = &dev.active_config {
        for iface in &cfg.interfaces {
            for driver in &drivers {
                if driver.matches(dev, cfg, iface) {
                    match driver.bind(dev, cfg, iface) {
                        Ok(()) => {
                            crate::log_info!(
                                "[USB] Bound {} to interface {}",
                                driver.name(),
                                iface.iface.b_interface_number
                            );
                            break;
                        }
                        Err(e) => {
                            crate::log_warn!(
                                "[USB] Failed to bind {} to interface {}: {}",
                                driver.name(),
                                iface.iface.b_interface_number,
                                e
                            );
                        }
                    }
                }
            }
        }
    }
}

pub fn interface_matches(
    iface: &UsbInterfaceInfo,
    class: u8,
    subclass: Option<u8>,
    protocol: Option<u8>,
) -> bool {
    if iface.iface.b_interface_class != class {
        return false;
    }
    if let Some(sub) = subclass {
        if iface.iface.b_interface_sub_class != sub {
            return false;
        }
    }
    if let Some(proto) = protocol {
        if iface.iface.b_interface_protocol != proto {
            return false;
        }
    }
    true
}

pub fn device_matches_vid_pid(dev: &UsbDevice, vid: u16, pid: u16) -> bool {
    dev.vendor_id() == vid && dev.product_id() == pid
}

pub fn device_matches_vid_pid_list(dev: &UsbDevice, list: &[(u16, u16)]) -> bool {
    list.iter().any(|&(vid, pid)| device_matches_vid_pid(dev, vid, pid))
}
