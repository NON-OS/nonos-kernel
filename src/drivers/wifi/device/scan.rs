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
use alloc::vec;
use alloc::vec::Vec;
use super::super::constants::*;
use super::super::error::WifiError;
use super::super::scan::{ScanConfig, ScanResult, SecurityType};
use super::intel::IntelWifiDevice;
use super::types::WifiState;

impl IntelWifiDevice {
    pub fn scan(&mut self, config: ScanConfig) -> Result<Vec<ScanResult>, WifiError> {
        match self.state {
            WifiState::Ready | WifiState::Connected | WifiState::FwLoaded => {}
            WifiState::HwReady => {
                crate::log::info!("iwlwifi: Scan requested but firmware not loaded");
                return Ok(Vec::new());
            }
            _ => return Err(WifiError::InvalidState),
        }

        self.state = WifiState::Scanning;
        self.scan_results.clear();

        let scan_cmd = self.build_scan_cmd(&config);
        self.send_cmd(cmd::SCAN_REQ_UMAC, &scan_cmd)?;

        let timeout_us = SCAN_TIMEOUT_MS * 1000;
        let start = Self::timestamp();

        while Self::timestamp() - start < timeout_us {
            self.process_rx()?;

            if self.state != WifiState::Scanning {
                break;
            }

            core::hint::spin_loop();
        }

        if self.state == WifiState::Scanning {
            self.send_cmd(cmd::SCAN_ABORT_UMAC, &[])?;
            self.state = WifiState::Ready;
            return Err(WifiError::Timeout);
        }

        self.state = WifiState::Ready;
        Ok(self.scan_results.clone())
    }

    pub(crate) fn build_scan_cmd(&self, config: &ScanConfig) -> Vec<u8> {
        let mut cmd = vec![0u8; SCAN_CMD_SIZE];

        cmd[0] = 0x01;
        cmd[1] = 0x00;
        cmd[2] = config.dwell_time_active as u8;
        cmd[3] = config.dwell_time_passive as u8;

        let mut ch_offset = 32;
        for ch in &config.channels {
            if ch_offset + 4 > cmd.len() {
                break;
            }
            cmd[ch_offset] = *ch;
            cmd[ch_offset + 1] = 0x01;
            ch_offset += 4;
        }

        cmd[4] = ((ch_offset - 32) / 4) as u8;

        cmd
    }

    pub(crate) fn parse_scan_result(&self, data: &[u8]) -> Result<ScanResult, WifiError> {
        if data.len() < 48 {
            return Err(WifiError::InvalidParameter);
        }

        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&data[0..6]);

        let channel = data[6];
        let rssi = data[7] as i8;

        let ssid_len = data[8] as usize;
        let ssid = if ssid_len > 0 && ssid_len <= 32 {
            String::from_utf8_lossy(&data[9..9 + ssid_len]).into_owned()
        } else {
            String::new()
        };

        let security = data[42];
        let security_type = match security & 0x0F {
            0 => SecurityType::Open,
            1 => SecurityType::Wep,
            2 => SecurityType::WpaPsk,
            3 => SecurityType::Wpa2Psk,
            4 => SecurityType::Wpa3Sae,
            _ => SecurityType::Unknown,
        };

        Ok(ScanResult {
            ssid,
            bssid,
            channel,
            rssi,
            security: security_type,
        })
    }
}
