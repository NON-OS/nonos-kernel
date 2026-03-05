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
use spin::Mutex;

use super::super::device::{IntelWifiDevice, RealtekWifiDevice, WifiState};
use super::super::error::WifiError;
use super::firmware::_load_firmware_from_disk;
use super::init::{connect, get_device, get_realtek_device, is_realtek};
use crate::network::stack::device::{SmolDevice, register_device};

pub(super) static _WIFI_NETWORK_DEVICE: spin::Once<_WifiNetworkDevice> = spin::Once::new();
pub(super) static _REALTEK_WIFI_NETWORK_DEVICE: spin::Once<_RealtekWifiNetworkDevice> = spin::Once::new();

pub(super) struct _WifiNetworkDevice {
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

pub(super) struct _RealtekWifiNetworkDevice {
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

pub(super) fn _register_with_network_stack() -> Result<(), WifiError> {
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

pub(super) fn _full_init(ssid: &str, password: &str) -> Result<(), WifiError> {
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
