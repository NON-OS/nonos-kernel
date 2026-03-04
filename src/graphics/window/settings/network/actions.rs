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

use core::sync::atomic::Ordering;
use crate::drivers::wifi;

use super::state::*;

pub fn do_load_firmware() {
    LOADING_FIRMWARE.store(true, Ordering::Relaxed);
    *CONNECTION_ERROR.lock() = None;

    match wifi::try_load_firmware() {
        Ok(()) => {
            *CONNECTION_ERROR.lock() = Some("Firmware loaded - try scanning now");
        }
        Err(e) => {
            let msg = match e {
                wifi::WifiError::FirmwareNotFound => "No firmware found - place WiFi firmware on USB",
                wifi::WifiError::FirmwareInvalid => "Invalid firmware file",
                wifi::WifiError::FirmwareLoadFailed => "Failed to load firmware into device",
                wifi::WifiError::NotInitialized => "WiFi device not initialized",
                _ => "Firmware loading failed",
            };
            *CONNECTION_ERROR.lock() = Some(msg);
        }
    }

    LOADING_FIRMWARE.store(false, Ordering::Relaxed);
}

pub fn do_wifi_scan() {
    WIFI_SCANNING.store(true, Ordering::Relaxed);
    *CONNECTION_ERROR.lock() = None;

    match wifi::scan() {
        Ok(results) => {
            let mut cached = CACHED_SCAN_RESULTS.lock();
            cached.clear();
            for r in results {
                cached.push(r);
            }
            if cached.is_empty() {
                *CONNECTION_ERROR.lock() = Some("No networks found - firmware may be required");
            }
        }
        Err(e) => {
            let msg = match e {
                wifi::WifiError::InvalidState => "Firmware not loaded - driver in standby",
                wifi::WifiError::Timeout => "Scan timed out",
                wifi::WifiError::HardwareError => "Hardware error",
                wifi::WifiError::RfKill => "WiFi radio disabled (RF kill)",
                wifi::WifiError::NotInitialized => "WiFi not initialized",
                _ => "Scan failed",
            };
            *CONNECTION_ERROR.lock() = Some(msg);
        }
    }

    WIFI_SCANNING.store(false, Ordering::Relaxed);
}

pub fn do_wifi_disconnect() {
    let _ = wifi::disconnect();
}

pub fn do_wifi_connect_open() {
    let results = CACHED_SCAN_RESULTS.lock();
    let idx = SELECTED_NETWORK.load(Ordering::Relaxed) as usize;

    if let Some(network) = results.get(idx) {
        let ssid = network.ssid.clone();
        drop(results);

        CONNECTING.store(true, Ordering::Relaxed);
        match wifi::connect(&ssid, "") {
            Ok(()) => {
                *CONNECTION_ERROR.lock() = None;
            }
            Err(_e) => {
                *CONNECTION_ERROR.lock() = Some("Connection failed");
            }
        }
        CONNECTING.store(false, Ordering::Relaxed);
    }
}

pub fn do_wifi_connect() {
    let results = CACHED_SCAN_RESULTS.lock();
    let idx = SELECTED_NETWORK.load(Ordering::Relaxed) as usize;

    if let Some(network) = results.get(idx) {
        let ssid = network.ssid.clone();
        drop(results);

        let pwd_len = PASSWORD_LEN.load(Ordering::Relaxed) as usize;
        let pwd_buf = PASSWORD_BUFFER.lock();
        let password = core::str::from_utf8(&pwd_buf[..pwd_len]).unwrap_or("");

        CONNECTING.store(true, Ordering::Relaxed);
        match wifi::connect(&ssid, password) {
            Ok(()) => {
                SHOW_PASSWORD_DIALOG.store(false, Ordering::Relaxed);
                *CONNECTION_ERROR.lock() = None;
            }
            Err(_e) => {
                *CONNECTION_ERROR.lock() = Some("Wrong password or connection failed");
            }
        }
        CONNECTING.store(false, Ordering::Relaxed);
    }
}
