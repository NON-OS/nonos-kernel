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

pub use super::super::wifi::{
    connect as wifi_connect, device_count as wifi_device_count, disconnect as wifi_disconnect,
    get_device as get_wifi_device, get_realtek_device as get_realtek_wifi_device,
    init as init_wifi, is_available as wifi_is_available, is_connected as wifi_is_connected,
    is_realtek as wifi_is_realtek, load_firmware_from_disk as wifi_load_firmware,
    print_status as print_wifi_status, scan as wifi_scan,
    try_load_firmware as wifi_try_load_firmware, IntelWifiDevice, LinkInfo, RealtekWifiDevice,
    ScanConfig, ScanResult, WifiError, WifiState,
};
