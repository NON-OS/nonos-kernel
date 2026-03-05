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
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::Mutex;

use super::super::constants::{INTEL_VENDOR_ID, SUPPORTED_DEVICE_IDS};
use super::super::device::{IntelWifiDevice, RealtekWifiDevice, WifiState};
use super::super::device::realtek::{REALTEK_VENDOR_ID, REALTEK_WIFI_DEVICE_IDS};
use super::super::error::WifiError;
use super::super::scan::{ScanConfig, ScanResult};
use super::types::{
    LinkInfo, DEVICE_COUNT, IS_REALTEK, REALTEK_WIFI_DEVICE, WIFI_DEVICE, WIFI_INITIALIZED,
};

pub fn init() -> usize {
    let devices = crate::drivers::pci::scan_and_collect();
    let mut count = 0;

    for pci_dev in devices.iter() {
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

            match IntelWifiDevice::new(pci_dev.clone()) {
                Ok(dev) => {
                    let arc = Arc::new(Mutex::new(dev));
                    WIFI_DEVICE.call_once(|| arc.clone());
                    WIFI_INITIALIZED.store(true, Ordering::SeqCst);
                    IS_REALTEK.store(false, Ordering::SeqCst);
                    count += 1;
                    break;
                }
                Err(e) => {
                    crate::log_warn!("iwlwifi: Failed to init device: {:?}", e);
                }
            }
        }
    }

    if count == 0 {
        for pci_dev in devices.iter() {
            if pci_dev.vendor_id() == REALTEK_VENDOR_ID
                && REALTEK_WIFI_DEVICE_IDS.contains(&pci_dev.device_id_value())
            {
                crate::log::info!(
                    "rtlwifi: Found Realtek WiFi {:04x}:{:04x} at {:02x}:{:02x}.{}",
                    pci_dev.vendor_id(),
                    pci_dev.device_id_value(),
                    pci_dev.bus(),
                    pci_dev.device(),
                    pci_dev.function()
                );

                match RealtekWifiDevice::new(pci_dev.clone()) {
                    Ok(dev) => {
                        let arc = Arc::new(Mutex::new(dev));
                        REALTEK_WIFI_DEVICE.call_once(|| arc.clone());
                        WIFI_INITIALIZED.store(true, Ordering::SeqCst);
                        IS_REALTEK.store(true, Ordering::SeqCst);
                        count += 1;
                        break;
                    }
                    Err(e) => {
                        crate::log_warn!("rtlwifi: Failed to init device: {:?}", e);
                    }
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

pub fn get_realtek_device() -> Option<Arc<Mutex<RealtekWifiDevice>>> {
    REALTEK_WIFI_DEVICE.get().cloned()
}

pub fn is_realtek() -> bool {
    IS_REALTEK.load(Ordering::Relaxed)
}

pub fn scan() -> Result<Vec<ScanResult>, WifiError> {
    if is_realtek() {
        let dev = get_realtek_device().ok_or(WifiError::NotInitialized)?;
        let mut guard = dev.lock();
        guard.scan(ScanConfig::default())
    } else {
        let dev = get_device().ok_or(WifiError::NotInitialized)?;
        let mut guard = dev.lock();
        guard.scan(ScanConfig::default())
    }
}

pub fn connect(ssid: &str, password: &str) -> Result<(), WifiError> {
    if is_realtek() {
        let dev = get_realtek_device().ok_or(WifiError::NotInitialized)?;
        {
            let mut guard = dev.lock();
            guard.connect(ssid, password)?;
        }
        super::network::_register_with_network_stack()
    } else {
        let dev = get_device().ok_or(WifiError::NotInitialized)?;
        {
            let mut guard = dev.lock();
            guard.connect(ssid, password)?;
        }
        super::network::_register_with_network_stack()
    }
}

pub fn disconnect() -> Result<(), WifiError> {
    if is_realtek() {
        let dev = get_realtek_device().ok_or(WifiError::NotInitialized)?;
        let mut guard = dev.lock();
        guard.disconnect()
    } else {
        let dev = get_device().ok_or(WifiError::NotInitialized)?;
        let mut guard = dev.lock();
        guard.disconnect()
    }
}

pub fn is_connected() -> bool {
    if is_realtek() {
        if let Some(dev) = get_realtek_device() {
            let guard = dev.lock();
            guard.state() == WifiState::Connected
        } else {
            false
        }
    } else {
        if let Some(dev) = get_device() {
            let guard = dev.lock();
            guard.state() == WifiState::Connected
        } else {
            false
        }
    }
}

pub fn get_link_info() -> Option<LinkInfo> {
    if is_realtek() {
        let dev = get_realtek_device()?;
        let guard = dev.lock();
        guard.get_link_info()
    } else {
        let dev = get_device()?;
        let guard = dev.lock();
        guard.get_link_info()
    }
}

pub fn print_status() {
    if !is_available() {
        crate::log::info!("wifi: No WiFi adapter detected");
        return;
    }

    if is_realtek() {
        if let Some(dev) = get_realtek_device() {
            let guard = dev.lock();
            crate::log::info!("rtlwifi: {} - {:?}", guard.device_name(), guard.state());
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
    } else {
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
}

fn is_supported_device(device_id: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&device_id)
}
