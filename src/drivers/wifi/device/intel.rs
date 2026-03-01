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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
use super::super::ccmp::CcmpContext;
use super::super::dma::{RxQueue, TxQueue};
use super::super::firmware::{Firmware, FirmwareLoader};
use super::super::pcie::PcieTransport;
use super::super::scan::{ScanResult, SecurityType};
use super::super::wpa::WpaContext;
use super::types::{WifiState, PowerConfig};

pub struct IntelWifiDevice {
    pub(crate) trans: PcieTransport,
    pub(crate) state: WifiState,
    pub(crate) firmware: Option<Firmware>,
    pub(crate) fw_loader: FirmwareLoader,
    pub(crate) tx_queues: Vec<TxQueue>,
    pub(crate) rx_queue: Option<RxQueue>,
    pub(crate) cmd_queue: Option<TxQueue>,
    pub(crate) device_id: u16,
    pub(crate) mac_address: [u8; 6],
    pub(crate) current_ssid: Option<String>,
    pub(crate) current_bssid: Option<[u8; 6]>,
    pub(crate) current_channel: u8,
    pub(crate) current_security: SecurityType,
    pub(crate) rssi: i8,
    pub(crate) scan_results: Vec<ScanResult>,
    pub(crate) seq_num: AtomicU32,
    pub(crate) wpa_context: Option<WpaContext>,
    pub(crate) ccmp_context: Option<CcmpContext>,
    pub(crate) power_config: PowerConfig,
    pub(crate) power_save_enabled: bool,
}
