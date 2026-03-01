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

//! WiFi public API.
//!
//! Provides WiFi connectivity with smoltcp network stack integration.
//! Supports Intel and Realtek WiFi adapters.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use super::constants::{INTEL_VENDOR_ID, SUPPORTED_DEVICE_IDS};
use super::device::{IntelWifiDevice, RealtekWifiDevice, WifiState};
use super::device::realtek::{REALTEK_VENDOR_ID, REALTEK_WIFI_DEVICE_IDS};
use super::error::WifiError;
use super::scan::{ScanConfig, ScanResult};
use crate::network::stack::device::{SmolDevice, register_device};
use crate::storage::fat32;
use crate::storage::block::{BlockDeviceType, BlockError, BlockResult, get_device as block_get_device};

pub enum WifiDeviceType {
    Intel(Arc<Mutex<IntelWifiDevice>>),
    Realtek(Arc<Mutex<RealtekWifiDevice>>),
}

static WIFI_DEVICE: spin::Once<Arc<Mutex<IntelWifiDevice>>> = spin::Once::new();
static REALTEK_WIFI_DEVICE: spin::Once<Arc<Mutex<RealtekWifiDevice>>> = spin::Once::new();
static _WIFI_NETWORK_DEVICE: spin::Once<_WifiNetworkDevice> = spin::Once::new();
static _REALTEK_WIFI_NETWORK_DEVICE: spin::Once<_RealtekWifiNetworkDevice> = spin::Once::new();
static WIFI_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);
static IS_REALTEK: AtomicBool = AtomicBool::new(false);

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
        let mut guard = dev.lock();
        guard.connect(ssid, password)
    } else {
        let dev = get_device().ok_or(WifiError::NotInitialized)?;
        let mut guard = dev.lock();
        guard.connect(ssid, password)
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

pub fn try_load_firmware() -> Result<(), WifiError> {
    if !is_available() {
        return Err(WifiError::NotInitialized);
    }

    for fs_id in 0..8 {
        match load_firmware_from_disk(fs_id) {
            Ok(()) => {
                crate::log::info!("wifi: Firmware loaded from filesystem {}", fs_id);
                return Ok(());
            }
            Err(WifiError::FirmwareNotFound) => continue,
            Err(e) => {
                crate::log_warn!("wifi: Firmware load error on fs {}: {:?}", fs_id, e);
            }
        }
    }

    Err(WifiError::FirmwareNotFound)
}

pub fn load_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    if is_realtek() {
        load_realtek_firmware_from_disk(fs_id)
    } else {
        load_intel_firmware_from_disk(fs_id)
    }
}

fn load_intel_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;

    let fs = fat32::get_fs(fs_id).ok_or(WifiError::FirmwareNotFound)?;

    let firmware_names: [&[u8]; 6] = [
        b"IWLWIFI.BIN",
        b"FIRMWARE.BIN",
        b"IWLCC77.BIN",
        b"IWLAX21.BIN",
        b"IWL8265.BIN",
        b"IWL9260.BIN",
    ];

    for name in &firmware_names {
        match fat32::find_file(&fs, *name, block_read_for_fw) {
            Ok(Some(entry)) => {
                let mut fw_buf = alloc::vec![0u8; entry.file_size as usize];
                match fat32::read_file(&fs, &entry, &mut fw_buf, block_read_for_fw) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            crate::log::info!("iwlwifi: Loading firmware ({} bytes)", bytes_read);
                            let mut guard = dev.lock();
                            return guard.load_firmware(&fw_buf[..bytes_read]);
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }

    Err(WifiError::FirmwareNotFound)
}

fn load_realtek_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    let dev = get_realtek_device().ok_or(WifiError::NotInitialized)?;

    let fs = fat32::get_fs(fs_id).ok_or(WifiError::FirmwareNotFound)?;

    let firmware_names: [&[u8]; 6] = [
        b"RTW88FW.BIN",
        b"RTW89FW.BIN",
        b"RTL8821.BIN",
        b"RTL8822.BIN",
        b"RTL8852.BIN",
        b"RTLWIFI.BIN",
    ];

    for name in &firmware_names {
        match fat32::find_file(&fs, *name, block_read_for_fw) {
            Ok(Some(entry)) => {
                let mut fw_buf = alloc::vec![0u8; entry.file_size as usize];
                match fat32::read_file(&fs, &entry, &mut fw_buf, block_read_for_fw) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            crate::log::info!("rtlwifi: Loading firmware ({} bytes)", bytes_read);
                            let mut guard = dev.lock();
                            return guard.load_firmware(&fw_buf[..bytes_read]);
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }

    Err(WifiError::FirmwareNotFound)
}

fn block_read_for_fw(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        _ => Err(BlockError::NotReady),
    }
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


pub(crate) fn _load_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;

    let fs = fat32::get_fs(fs_id).ok_or(WifiError::FirmwareNotFound)?;

    let firmware_names: [&[u8]; 4] = [
        b"IWLWIFI.BIN",     // Short 8.3 name
        b"FIRMWARE.BIN",    // Generic name
        b"IWLCC77.BIN",     // AX200/201 firmware
        b"IWLAX21.BIN",     // AX210/211 firmware
    ];

    for name in &firmware_names {
        match fat32::find_file(&fs, *name, _block_read) {
            Ok(Some(entry)) => {
                let mut fw_buf = alloc::vec![0u8; entry.file_size as usize];
                match fat32::read_file(&fs, &entry, &mut fw_buf, _block_read) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            crate::log::info!("iwlwifi: Loading firmware from disk ({} bytes)", bytes_read);
                            let mut guard = dev.lock();
                            return guard.load_firmware(&fw_buf[..bytes_read]);
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }

    crate::log_warn!("iwlwifi: No firmware file found on disk {}", fs_id);
    Err(WifiError::FirmwareNotFound)
}

fn _block_read(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        _ => Err(BlockError::NotReady),
    }
}


pub(crate) struct _WifiNetworkDevice {
    device: Arc<Mutex<IntelWifiDevice>>,
}

impl _WifiNetworkDevice {
    fn new(device: Arc<Mutex<IntelWifiDevice>>) -> Self {
        Self { device }
    }
}

impl SmolDevice for _WifiNetworkDevice {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut guard = self.device.lock();
        match guard.receive() {
            Ok(Some(data)) => Some(data),
            _ => None,
        }
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        let mut guard = self.device.lock();
        guard.transmit(frame).map_err(|_| ())
    }

    fn mac(&self) -> [u8; 6] {
        let guard = self.device.lock();
        guard.mac_address()
    }

    fn link_mtu(&self) -> usize {
        1500
    }
}

pub(crate) struct _RealtekWifiNetworkDevice {
    device: Arc<Mutex<RealtekWifiDevice>>,
}

impl _RealtekWifiNetworkDevice {
    fn new(device: Arc<Mutex<RealtekWifiDevice>>) -> Self {
        Self { device }
    }
}

impl SmolDevice for _RealtekWifiNetworkDevice {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut guard = self.device.lock();
        match guard.receive() {
            Ok(Some(data)) => Some(data),
            _ => None,
        }
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        let mut guard = self.device.lock();
        guard.transmit(frame).map_err(|_| ())
    }

    fn mac(&self) -> [u8; 6] {
        let guard = self.device.lock();
        guard.mac_address()
    }

    fn link_mtu(&self) -> usize {
        1500
    }
}

pub(crate) fn _register_with_network_stack() -> Result<(), WifiError> {
    if is_realtek() {
        let dev = get_realtek_device().ok_or(WifiError::NotInitialized)?;

        {
            let guard = dev.lock();
            if guard.state() != WifiState::Connected {
                return Err(WifiError::NotConnected);
            }
        }

        _REALTEK_WIFI_NETWORK_DEVICE.call_once(|| _RealtekWifiNetworkDevice::new(dev.clone()));

        if let Some(net_dev) = _REALTEK_WIFI_NETWORK_DEVICE.get() {
            // SAFETY: _RealtekWifiNetworkDevice is 'static and Send+Sync
            register_device(unsafe {
                &*(net_dev as *const _RealtekWifiNetworkDevice)
            });
            crate::log::info!("rtlwifi: Registered with network stack");
            Ok(())
        } else {
            Err(WifiError::InvalidState)
        }
    } else {
        let dev = get_device().ok_or(WifiError::NotInitialized)?;

        {
            let guard = dev.lock();
            if guard.state() != WifiState::Connected {
                return Err(WifiError::NotConnected);
            }
        }

        _WIFI_NETWORK_DEVICE.call_once(|| _WifiNetworkDevice::new(dev.clone()));

        if let Some(net_dev) = _WIFI_NETWORK_DEVICE.get() {
            // SAFETY: _WifiNetworkDevice is 'static and Send+Sync
            register_device(unsafe {
                &*(net_dev as *const _WifiNetworkDevice)
            });
            crate::log::info!("iwlwifi: Registered with network stack");
            Ok(())
        } else {
            Err(WifiError::InvalidState)
        }
    }
}

pub(crate) fn _full_init(ssid: &str, password: &str) -> Result<(), WifiError> {
    for fs_id in 0..4 {
        if _load_firmware_from_disk(fs_id).is_ok() {
            break;
        }
    }

    connect(ssid, password)?;

    _register_with_network_stack()?;

    crate::log::info!("iwlwifi: Full initialization complete");
    Ok(())
}
