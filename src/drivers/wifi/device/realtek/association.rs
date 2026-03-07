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
IEEE 802.11 association frame construction and response parsing for Realtek chipsets.
Builds association requests with RSN IE for WPA2/WPA3 security negotiation.
*/

extern crate alloc;

use alloc::vec;

use super::super::super::error::WifiError;
use super::super::super::scan::SecurityType;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
    pub(crate) fn send_association_request(&mut self, ssid: &str, bssid: &[u8; 6]) -> Result<(), WifiError> {
        let ssid_bytes = ssid.as_bytes();
        let frame_len = 24 + 4 + 2 + ssid_bytes.len() + 10 + 22;
        let mut frame = vec![0u8; frame_len];

        frame[0] = 0x00;
        frame[1] = 0x00;
        frame[2..4].copy_from_slice(&[0x00, 0x00]);
        frame[4..10].copy_from_slice(bssid);
        frame[10..16].copy_from_slice(&self.mac_address);
        frame[16..22].copy_from_slice(bssid);
        frame[22..24].copy_from_slice(&[0x00, 0x00]);

        frame[24] = 0x31;
        frame[25] = 0x04;
        frame[26] = 0x0a;
        frame[27] = 0x00;

        let mut offset = 28;

        frame[offset] = 0x00;
        frame[offset + 1] = ssid_bytes.len() as u8;
        frame[offset + 2..offset + 2 + ssid_bytes.len()].copy_from_slice(ssid_bytes);
        offset += 2 + ssid_bytes.len();

        frame[offset] = 0x01;
        frame[offset + 1] = 0x08;
        frame[offset + 2..offset + 10].copy_from_slice(&[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
        offset += 10;

        if self.current_security == SecurityType::Wpa2Psk || self.current_security == SecurityType::Wpa3Sae {
            frame[offset] = 0x30;
            frame[offset + 1] = 0x14;
            frame[offset + 2..offset + 4].copy_from_slice(&[0x01, 0x00]);
            frame[offset + 4..offset + 8].copy_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
            frame[offset + 8..offset + 10].copy_from_slice(&[0x01, 0x00]);
            frame[offset + 10..offset + 14].copy_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
            frame[offset + 14..offset + 16].copy_from_slice(&[0x01, 0x00]);
            frame[offset + 16..offset + 20].copy_from_slice(&[0x00, 0x0f, 0xac, 0x02]);
            frame[offset + 20..offset + 22].copy_from_slice(&[0x00, 0x00]);
            offset += 22;
        }

        self.transmit_raw(&frame[..offset])
    }

    pub(crate) fn wait_for_association(&mut self) -> Result<(), WifiError> {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        let timeout_us = 5_000_000u64;

        while crate::arch::x86_64::time::tsc::elapsed_us() - start < timeout_us {
            let frames = self.process_rx_ring();
            for frame in frames {
                if frame.len() >= 28 {
                    let frame_type = frame[0] & 0xFC;
                    if frame_type == 0x10 {
                        let status = u16::from_le_bytes([frame[26], frame[27]]);
                        if status == 0 {
                            return Ok(());
                        } else {
                            crate::log_warn!("rtlwifi: Association rejected, status {}", status);
                            return Err(WifiError::AssociationFailed);
                        }
                    }
                }
            }
            self.delay_us(1000);
        }
        Err(WifiError::Timeout)
    }
}
