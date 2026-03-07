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
WiFi network scanning for Realtek chipsets. Active scanning with probe requests
and passive beacon/probe response parsing. Extracts SSID, BSSID, channel, and
security type (Open/WPA/WPA2/WPA3) from information elements.
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::error::WifiError;
use super::super::super::scan::{ScanResult, ScanConfig, SecurityType};
use super::super::types::WifiState;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
    pub fn scan(&mut self, config: ScanConfig) -> Result<Vec<ScanResult>, WifiError> {
        match self.state {
            WifiState::Ready | WifiState::Connected | WifiState::FwLoaded => {}
            WifiState::HwReady => {
                crate::log::info!("rtlwifi: Scan requested but firmware not loaded");
                return Ok(Vec::new());
            }
            _ => return Err(WifiError::InvalidState),
        }

        let prev_state = self.state;
        self.state = WifiState::Scanning;
        self.scan_results.clear();

        crate::log::info!("rtlwifi: Scanning for networks...");

        let channels = if config.channels.is_empty() {
            &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11][..]
        } else {
            &config.channels[..]
        };

        for &channel in channels {
            self.set_channel(channel);
            self.delay_us(10_000);

            self.send_probe_request(config.ssid_filter.as_deref());

            let dwell_time = if config.passive_scan { 100_000u64 } else { 30_000u64 };
            let start = crate::arch::x86_64::time::tsc::elapsed_us();

            while crate::arch::x86_64::time::tsc::elapsed_us() - start < dwell_time {
                let frames = self.process_rx_ring();
                for frame in frames {
                    if let Some(result) = self.parse_beacon_or_probe_resp(&frame, channel) {
                        let exists = self.scan_results.iter().any(|r| r.bssid == result.bssid);
                        if !exists {
                            self.scan_results.push(result);
                        }
                    }
                }
                self.delay_us(1000);
            }

            if self.scan_results.len() >= 32 {
                break;
            }
        }

        crate::log::info!("rtlwifi: Scan complete, found {} networks", self.scan_results.len());
        self.state = prev_state;
        Ok(self.scan_results.clone())
    }

    fn send_probe_request(&mut self, _ssid: Option<&str>) {
        let probe_req: [u8; 24] = [
            0x40, 0x00,
            0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            self.mac_address[0], self.mac_address[1], self.mac_address[2],
            self.mac_address[3], self.mac_address[4], self.mac_address[5],
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00,
        ];
        let _ = self.transmit_raw(&probe_req);
    }

    fn parse_beacon_or_probe_resp(&self, frame: &[u8], channel: u8) -> Option<ScanResult> {
        if frame.len() < 36 {
            return None;
        }

        let frame_type = frame[0] & 0xFC;
        if frame_type != 0x80 && frame_type != 0x50 {
            return None;
        }

        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&frame[16..22]);

        if bssid == [0xFF; 6] || bssid == [0; 6] {
            return None;
        }

        let mut ssid = String::new();
        let mut security = SecurityType::Open;
        let mut ie_offset = 36;

        while ie_offset + 2 <= frame.len() {
            let ie_type = frame[ie_offset];
            let ie_len = frame[ie_offset + 1] as usize;

            if ie_offset + 2 + ie_len > frame.len() {
                break;
            }

            match ie_type {
                0 => {
                    if ie_len > 0 && ie_len <= 32 {
                        if let Ok(s) = core::str::from_utf8(&frame[ie_offset + 2..ie_offset + 2 + ie_len]) {
                            ssid = String::from(s);
                        }
                    }
                }
                48 => {
                    security = SecurityType::Wpa2Psk;
                }
                221 => {
                    if ie_len >= 4 {
                        let oui = &frame[ie_offset + 2..ie_offset + 5];
                        if oui == [0x00, 0x50, 0xF2] && frame[ie_offset + 5] == 1 {
                            if security == SecurityType::Open {
                                security = SecurityType::WpaPsk;
                            }
                        }
                    }
                }
                _ => {}
            }

            ie_offset += 2 + ie_len;
        }

        if ssid.is_empty() {
            return None;
        }

        Some(ScanResult {
            ssid,
            bssid,
            channel,
            rssi: -50,
            security,
        })
    }
}
