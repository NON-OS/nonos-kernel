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
use core::sync::atomic::{AtomicBool, AtomicU32};
use spin::Mutex;

use super::super::device::{IntelWifiDevice, RealtekWifiDevice};

pub enum WifiDeviceType {
    Intel(Arc<Mutex<IntelWifiDevice>>),
    Realtek(Arc<Mutex<RealtekWifiDevice>>),
}

pub static WIFI_DEVICE: spin::Once<Arc<Mutex<IntelWifiDevice>>> = spin::Once::new();
pub static REALTEK_WIFI_DEVICE: spin::Once<Arc<Mutex<RealtekWifiDevice>>> = spin::Once::new();
pub static WIFI_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);
pub static IS_REALTEK: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub ssid: alloc::string::String,
    pub bssid: [u8; 6],
    pub channel: u8,
    pub rssi: i8,
    pub tx_rate: u32,
    pub rx_rate: u32,
}
