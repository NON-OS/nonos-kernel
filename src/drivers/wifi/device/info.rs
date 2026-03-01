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

use super::super::firmware::FirmwareInfo;
use super::super::LinkInfo;
use super::intel::IntelWifiDevice;
use super::types::WifiState;

impl IntelWifiDevice {
    pub fn state(&self) -> WifiState {
        self.state
    }

    pub fn device_name(&self) -> &'static str {
        match self.device_id {
            0x2723 | 0x2725 | 0x34F0 | 0x3DF0 | 0x4DF0 => "Intel WiFi 6 AX200/201",
            0x2729 | 0x272B | 0x51F0 | 0x51F1 | 0x54F0 => "Intel WiFi 6E AX210/211",
            0x2526 | 0x9DF0 | 0xA370 | 0x31DC | 0x30DC => "Intel WiFi 5 9260/9560",
            0x24F3..=0x24FD => "Intel WiFi 5 8260/8265",
            0x08B1..=0x08B4 | 0x095A | 0x095B => "Intel WiFi 4 7260/7265",
            _ => "Intel WiFi",
        }
    }

    pub fn firmware_info(&self) -> Option<&FirmwareInfo> {
        self.firmware.as_ref().map(|fw| &fw.info)
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    pub fn get_link_info(&self) -> Option<LinkInfo> {
        if self.state != WifiState::Connected {
            return None;
        }

        let is_5ghz = self.current_channel >= 36;
        let rate = super::super::tx::select_tx_rate(self.rssi, is_5ghz);

        Some(LinkInfo {
            ssid: self.current_ssid.clone()?,
            bssid: self.current_bssid?,
            channel: self.current_channel,
            rssi: self.rssi,
            tx_rate: rate,
            rx_rate: rate,
        })
    }
}
