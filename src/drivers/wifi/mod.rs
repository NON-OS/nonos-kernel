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

/// #![allow(dead_code)]

extern crate alloc;
mod constants;
mod device;
mod dma;
mod error;
mod firmware;
mod pcie;
mod regs;
mod rx;
mod scan;
mod tx;

#[cfg(test)]
mod tests;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;
pub use constants::*;
pub use device::{IntelWifiDevice, WifiState};
pub use error::WifiError;
pub use firmware::FirmwareInfo;
pub use scan::{ScanConfig, ScanResult};

static WIFI_DEVICE: spin::Once<Arc<Mutex<IntelWifiDevice>>> = spin::Once::new();
static WIFI_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn init() -> usize {
    let devices = crate::drivers::pci::scan_and_collect();
    let mut count = 0;

    for pci_dev in devices {
        if pci_dev.vendor_id() == INTEL_VENDOR_ID && is_supported_device(pci_dev.device_id_value())
        {
            crate::log::info!(
                "iwlwifi: Found Intel WiFi {:04x}:{:04x} at {:02x}:{:02x}.{}",
                pci_dev.vendor_id(),
                pci_dev.device_id_value(),
                pci_dev.bus(),
                pci_dev.device(),
                pci_dev.function()
            );

            match IntelWifiDevice::new(pci_dev) {
                Ok(dev) => {
                    let arc = Arc::new(Mutex::new(dev));
                    WIFI_DEVICE.call_once(|| arc.clone());
                    WIFI_INITIALIZED.store(true, Ordering::SeqCst);
                    count += 1;
                    break;
                }
                Err(e) => {
                    crate::log_warn!("iwlwifi: Failed to init device: {:?}", e);
                }
            }
        }
    }

    DEVICE_COUNT.store(count as u32, Ordering::SeqCst);
    count
}

pub fn is_available() -> bool {
    WIFI_INITIALIZED.load(Ordering::Relaxed)
}

pub fn device_count() -> usize {
    DEVICE_COUNT.load(Ordering::Relaxed) as usize
}

pub fn get_device() -> Option<Arc<Mutex<IntelWifiDevice>>> {
    WIFI_DEVICE.get().cloned()
}

pub fn scan() -> Result<Vec<ScanResult>, WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;
    let mut guard = dev.lock();
    guard.scan(ScanConfig::default())
}

pub fn connect(ssid: &str, password: &str) -> Result<(), WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;
    let mut guard = dev.lock();
    guard.connect(ssid, password)
}

pub fn disconnect() -> Result<(), WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;
    let mut guard = dev.lock();
    guard.disconnect()
}

pub fn is_connected() -> bool {
    if let Some(dev) = get_device() {
        let guard = dev.lock();
        guard.state() == WifiState::Connected
    } else {
        false
    }
}

pub fn get_link_info() -> Option<LinkInfo> {
    let dev = get_device()?;
    let guard = dev.lock();
    guard.get_link_info()
}

pub fn print_status() {
    if !is_available() {
        crate::log::info!("iwlwifi: No Intel WiFi adapter detected");
        return;
    }

    if let Some(dev) = get_device() {
        let guard = dev.lock();
        crate::log::info!("iwlwifi: {} - {:?}", guard.device_name(), guard.state());
        if let Some(fw) = guard.firmware_info() {
            crate::log::info!("  Firmware: v{}.{}.{}", fw.major, fw.minor, fw.api);
        }
        if guard.state() == WifiState::Connected {
            if let Some(info) = guard.get_link_info() {
                crate::log::info!("  SSID: {}", info.ssid);
                crate::log::info!("  Signal: {} dBm", info.rssi);
                crate::log::info!("  Channel: {}", info.channel);
            }
        }
    }
}

fn is_supported_device(device_id: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&device_id)
}

#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub ssid: alloc::string::String,
    pub bssid: [u8; 6],
    pub channel: u8,
    pub rssi: i8,
    pub tx_rate: u32,
    pub rx_rate: u32,
}
