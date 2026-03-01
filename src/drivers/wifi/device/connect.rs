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

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use super::super::ccmp::CcmpContext;
use super::super::constants::*;
use super::super::error::WifiError;
use super::super::scan::{ScanResult, SecurityType};
use super::super::wpa::WpaContext;
use super::intel::IntelWifiDevice;
use super::types::WifiState;

impl IntelWifiDevice {
    pub fn connect(&mut self, ssid: &str, password: &str) -> Result<(), WifiError> {
        if self.state != WifiState::Ready {
            return Err(WifiError::InvalidState);
        }

        let target = self
            .scan_results
            .iter()
            .find(|r| r.ssid == ssid)
            .ok_or(WifiError::NoNetwork)?
            .clone();

        self.state = WifiState::Connecting;
        self.current_security = target.security;

        if target.security != SecurityType::Open {
            let mut wpa = WpaContext::new(target.security, self.mac_address, target.bssid);

            wpa.derive_pmk(password, ssid)?;

            crate::log::info!("iwlwifi: PMK derived for {} ({})", ssid, target.security.as_str());
            self.wpa_context = Some(wpa);
        }

        self.send_mac_context_cmd(&target)?;
        self.send_time_event_cmd()?;
        self.send_binding_cmd(&target)?;

        self.send_assoc_request(&target)?;

        let timeout_us = CONNECT_TIMEOUT_MS * 1000;
        let start = Self::timestamp();
        let mut handshake_complete = target.security == SecurityType::Open;

        while Self::timestamp() - start < timeout_us {
            self.process_rx()?;

            let (is_complete, temporal_key) = if let Some(ref wpa) = self.wpa_context {
                (wpa.is_complete(), wpa.get_temporal_key().map(|tk| tk.to_vec()))
            } else {
                (false, None)
            };

            if is_complete {
                handshake_complete = true;
                crate::log::info!("iwlwifi: 4-way handshake complete");

                if let Some(ref tk) = temporal_key {
                    self.install_pairwise_key(tk)?;

                    if tk.len() >= 16 {
                        let mut tk_arr = [0u8; 16];
                        tk_arr.copy_from_slice(&tk[..16]);
                        self.ccmp_context = Some(CcmpContext::new(&tk_arr));
                        crate::log::info!("iwlwifi: CCMP encryption context initialized");
                    }
                }
                break;
            }

            if handshake_complete {
                let int = self.trans.ack_interrupts();
                if int != 0 {
                    break;
                }
            }

            core::hint::spin_loop();
        }

        if !handshake_complete {
            self.wpa_context = None;
            self.state = WifiState::Ready;
            return Err(WifiError::HandshakeFailed);
        }

        self.current_ssid = Some(ssid.to_string());
        self.current_bssid = Some(target.bssid);
        self.current_channel = target.channel;
        self.rssi = target.rssi;
        self.state = WifiState::Connected;

        crate::log::info!(
            "iwlwifi: Connected to {} on channel {} ({})",
            ssid,
            target.channel,
            target.security.as_str()
        );
        Ok(())
    }

    pub(crate) fn send_assoc_request(&mut self, target: &ScanResult) -> Result<(), WifiError> {
        let mut cmd_data = vec![0u8; AUTH_CMD_SIZE];

        cmd_data[0..6].copy_from_slice(&target.bssid);
        cmd_data[6] = 0x00;

        cmd_data[7] = 0x11;
        cmd_data[8] = 0x04;

        cmd_data[9] = 10;
        cmd_data[10] = 0;

        let ssid_bytes = target.ssid.as_bytes();
        let ssid_len = ssid_bytes.len().min(32);
        cmd_data[12] = 0x00;
        cmd_data[13] = ssid_len as u8;
        cmd_data[14..14 + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);

        let rate_offset = 14 + ssid_len;
        cmd_data[rate_offset] = 0x01;
        cmd_data[rate_offset + 1] = 8;
        cmd_data[rate_offset + 2..rate_offset + 10].copy_from_slice(&[
            0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
        ]);

        if matches!(target.security, SecurityType::Wpa2Psk | SecurityType::Wpa3Sae) {
            let rsn_offset = rate_offset + 10;
            let rsn_ie = self.build_rsn_ie(target.security);
            cmd_data[rsn_offset..rsn_offset + rsn_ie.len()].copy_from_slice(&rsn_ie);
        }

        self.send_cmd(cmd::ADD_STA, &cmd_data)
    }

    pub(crate) fn build_rsn_ie(&self, security: SecurityType) -> Vec<u8> {
        let mut ie = Vec::with_capacity(26);

        ie.push(0x30);
        ie.push(0x14);

        ie.extend_from_slice(&[0x01, 0x00]);

        ie.extend_from_slice(&[0x00, 0x0f, 0xac]);
        if security == SecurityType::Wpa3Sae {
            ie.push(0x08);
        } else {
            ie.push(0x04);
        }

        ie.extend_from_slice(&[0x01, 0x00]);

        ie.extend_from_slice(&[0x00, 0x0f, 0xac]);
        if security == SecurityType::Wpa3Sae {
            ie.push(0x08);
        } else {
            ie.push(0x04);
        }

        ie.extend_from_slice(&[0x01, 0x00]);

        ie.extend_from_slice(&[0x00, 0x0f, 0xac]);
        if security == SecurityType::Wpa3Sae {
            ie.push(0x08);
        } else {
            ie.push(0x02);
        }

        ie.extend_from_slice(&[0x00, 0x00]);

        ie[1] = (ie.len() - 2) as u8;

        ie
    }

    pub(crate) fn install_pairwise_key(&mut self, tk: &[u8]) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 64];

        cmd_data[0] = 1;
        cmd_data[1] = 0;
        cmd_data[2] = 0;

        cmd_data[4] = 0x01;

        cmd_data[8] = tk.len().min(32) as u8;

        let key_len = tk.len().min(32);
        cmd_data[16..16 + key_len].copy_from_slice(&tk[..key_len]);

        if let Some(bssid) = self.current_bssid {
            cmd_data[48..54].copy_from_slice(&bssid);
        }

        self.send_cmd(cmd::ADD_STA_KEY, &cmd_data)
    }

    pub(crate) fn send_mac_context_cmd(&mut self, target: &ScanResult) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; MAC_CONTEXT_CMD_SIZE];
        cmd_data[0] = 1;
        cmd_data[1] = 1;
        cmd_data[2] = 0;
        cmd_data[4..10].copy_from_slice(&self.mac_address);
        cmd_data[16..22].copy_from_slice(&target.bssid);
        cmd_data[22] = 100;
        cmd_data[23] = 0;
        cmd_data[24] = 1;
        cmd_data[28] = 0x0F;
        cmd_data[32] = 0xFF;
        self.send_cmd(cmd::MAC_CONTEXT_CMD, &cmd_data)
    }

    pub(crate) fn send_time_event_cmd(&mut self) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 32];
        cmd_data[0] = 1;
        cmd_data[4] = 0;
        cmd_data[8] = 1;
        cmd_data[16] = 0xF4;
        cmd_data[17] = 0x01;
        cmd_data[28] = 0xE8;
        cmd_data[29] = 0x03;
        self.send_cmd(cmd::TIME_EVENT_CMD, &cmd_data)
    }

    pub(crate) fn send_binding_cmd(&mut self, target: &ScanResult) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 64];
        cmd_data[0] = 1;
        cmd_data[1] = 1;
        cmd_data[2] = 1;
        cmd_data[3] = 1;
        cmd_data[4] = target.channel;
        cmd_data[5] = if target.channel >= 36 { 1 } else { 0 };
        cmd_data[6] = 0;
        self.send_cmd(cmd::BINDING_CONTEXT_CMD, &cmd_data)
    }

    pub fn disconnect(&mut self) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Ok(());
        }

        self.state = WifiState::Disconnecting;

        let remove_cmd = [0u8; 8];
        self.send_cmd(cmd::REMOVE_STA, &remove_cmd)?;

        if let Some(ref mut wpa) = self.wpa_context {
            wpa.pmk.fill(0);
            wpa.ptk.fill(0);
        }
        self.wpa_context = None;

        self.current_ssid = None;
        self.current_bssid = None;
        self.current_channel = 0;
        self.current_security = SecurityType::Open;
        self.rssi = RSSI_INVALID;
        self.state = WifiState::Ready;

        crate::log::info!("iwlwifi: Disconnected");
        Ok(())
    }
}
