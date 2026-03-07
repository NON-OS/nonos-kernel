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
WPA3-SAE (Simultaneous Authentication of Equals) frame handling for Realtek.
Constructs and parses SAE commit/confirm authentication frames using the
Dragonfly key exchange protocol over P-256.
*/

extern crate alloc;

use alloc::vec::Vec;

use super::super::super::error::WifiError;
use super::super::super::wpa::sae::SaeCommit;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
    pub(crate) fn send_sae_commit(&mut self, commit: &SaeCommit) -> Result<(), WifiError> {
        let bssid = self.current_bssid.ok_or(WifiError::NotConnected)?;
        let mut frame = Vec::with_capacity(24 + 6 + 32 + 33);

        frame.extend_from_slice(&[0xB0, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&self.mac_address);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&[0x00, 0x00]);

        frame.extend_from_slice(&[0x03, 0x00]);
        frame.extend_from_slice(&[0x01, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]);

        frame.extend_from_slice(&commit.scalar);
        frame.extend_from_slice(&commit.element);

        self.transmit_raw(&frame)
    }

    pub(crate) fn wait_for_sae_commit(&mut self) -> Result<SaeCommit, WifiError> {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        let timeout_us = 5_000_000u64;

        while crate::arch::x86_64::time::tsc::elapsed_us() - start < timeout_us {
            let frames = self.process_rx_ring();
            for frame in frames {
                if frame.len() >= 24 + 6 + 32 + 33 {
                    let frame_type = frame[0] & 0xFC;
                    if frame_type == 0xB0 {
                        let auth_alg = u16::from_le_bytes([frame[24], frame[25]]);
                        let auth_seq = u16::from_le_bytes([frame[26], frame[27]]);
                        let status = u16::from_le_bytes([frame[28], frame[29]]);

                        if auth_alg == 0x03 && auth_seq == 0x01 && status == 0x00 {
                            let mut scalar = [0u8; 32];
                            let mut element = [0u8; 33];
                            scalar.copy_from_slice(&frame[30..62]);
                            element.copy_from_slice(&frame[62..95]);
                            return Ok(SaeCommit { scalar, element });
                        }
                    }
                }
            }
            self.delay_us(1000);
        }
        Err(WifiError::Timeout)
    }

    pub(crate) fn send_sae_confirm(&mut self, confirm: &[u8]) -> Result<(), WifiError> {
        let bssid = self.current_bssid.ok_or(WifiError::NotConnected)?;
        let mut frame = Vec::with_capacity(24 + 6 + confirm.len());

        frame.extend_from_slice(&[0xB0, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&self.mac_address);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&[0x00, 0x00]);

        frame.extend_from_slice(&[0x03, 0x00]);
        frame.extend_from_slice(&[0x02, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(confirm);

        self.transmit_raw(&frame)
    }

    pub(crate) fn wait_for_sae_confirm(&mut self) -> Result<Vec<u8>, WifiError> {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        let timeout_us = 5_000_000u64;

        while crate::arch::x86_64::time::tsc::elapsed_us() - start < timeout_us {
            let frames = self.process_rx_ring();
            for frame in frames {
                if frame.len() >= 24 + 6 + 34 {
                    let frame_type = frame[0] & 0xFC;
                    if frame_type == 0xB0 {
                        let auth_alg = u16::from_le_bytes([frame[24], frame[25]]);
                        let auth_seq = u16::from_le_bytes([frame[26], frame[27]]);
                        let status = u16::from_le_bytes([frame[28], frame[29]]);

                        if auth_alg == 0x03 && auth_seq == 0x02 && status == 0x00 {
                            return Ok(frame[30..].to_vec());
                        } else if status != 0x00 {
                            crate::log_warn!("rtlwifi: SAE confirm rejected, status {}", status);
                            return Err(WifiError::AuthenticationFailed);
                        }
                    }
                }
            }
            self.delay_us(1000);
        }
        Err(WifiError::Timeout)
    }
}
