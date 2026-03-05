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

extern crate alloc;

pub mod api;
pub mod ccmp;
pub mod constants;
pub mod device;
pub mod dma;
pub mod error;
pub mod firmware;
pub mod pcie;
pub mod regs;
pub mod rx;
pub mod scan;
pub mod smol_bridge;
pub mod tx;
pub mod wpa;

#[cfg(test)]
mod tests;

pub use api::{
    connect, device_count, disconnect, get_device, get_realtek_device, get_link_info,
    init, is_available, is_connected, is_realtek, load_firmware_from_disk, print_status,
    scan, try_load_firmware, LinkInfo,
};
pub use constants::*;
pub use device::{IntelWifiDevice, RealtekWifiDevice, WifiState};
pub use error::WifiError;
pub use firmware::FirmwareInfo;
pub use scan::{ScanConfig, ScanResult};
pub use smol_bridge::{
    is_registered, register_with_network_stack, unregister_from_network_stack, reset_stats,
    WiFiSmolBridge, WiFiStats, WIFI_SMOL_BRIDGE,
};
pub use rx::{_RxProcessor, _RxFrame, _RxFrameInfo, _FrameType};
