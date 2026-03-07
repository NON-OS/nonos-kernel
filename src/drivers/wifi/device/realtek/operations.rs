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

/*
Core Realtek WiFi device operations. Channel management, link status queries,
and interrupt handling. Higher-level functions split into connect, scan, io,
firmware, association, and sae modules.
*/

use super::super::super::api::LinkInfo;
use super::super::types::WifiState;
use super::constants::*;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
    pub fn state(&self) -> WifiState {
        self.state
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    pub fn device_name(&self) -> &'static str {
        match self.device_id {
            0xC821 => "Realtek RTL8821CE 802.11ac",
            0xC822 | 0xC82F | 0xC82C => "Realtek RTL8822CE 802.11ac",
            0xB822 | 0xB82B => "Realtek RTL8822BE 802.11ac",
            0xB852 | 0xC852 | 0xC862 => "Realtek RTL8852BE 802.11ax",
            0x8852 | 0xA852 => "Realtek RTL8852AE 802.11ax",
            0xD723 => "Realtek RTL8723DE 802.11n",
            0xB723 => "Realtek RTL8723BE 802.11n",
            0x8723 => "Realtek RTL8723AE 802.11n",
            0xC812 | 0x8812 | 0xB812 => "Realtek RTL8812 802.11ac",
            _ => "Realtek WiFi Adapter",
        }
    }

    pub(crate) fn set_channel(&mut self, channel: u8) {
        if channel < 1 || channel > 14 {
            return;
        }
        self.current_channel = channel;
        let freq = match channel {
            1 => 2412u16, 2 => 2417, 3 => 2422, 4 => 2427, 5 => 2432,
            6 => 2437, 7 => 2442, 8 => 2447, 9 => 2452, 10 => 2457,
            11 => 2462, 12 => 2467, 13 => 2472, 14 => 2484,
            _ => 2437,
        };
        let _ = freq;
    }

    pub fn get_link_info(&self) -> Option<LinkInfo> {
        if self.state != WifiState::Connected {
            return None;
        }

        Some(LinkInfo {
            ssid: self.current_ssid.clone().unwrap_or_default(),
            bssid: self.current_bssid.unwrap_or([0; 6]),
            channel: self.current_channel,
            rssi: self.rssi,
            tx_rate: 0,
            rx_rate: 0,
        })
    }

    pub fn handle_interrupt(&mut self) {
        let isr = self.read32(regs::HISR);
        if isr == 0 {
            return;
        }

        self.write32(regs::HISR, isr);
    }
}
