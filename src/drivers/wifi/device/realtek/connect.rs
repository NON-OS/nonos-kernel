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
Realtek WiFi connection and authentication. Implements WPA2-PSK 4-way handshake
and WPA3-SAE Dragonfly protocol. PMK derivation via PBKDF2-SHA1 for PSK networks.
Temporal keys installed to hardware CAM after successful authentication.
*/

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::error::WifiError;
use super::super::super::scan::SecurityType;
use super::super::super::wpa::context::WpaContext;
use super::super::super::wpa::eapol::parse_eapol_frame;
use super::super::types::WifiState;
use super::constants::*;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
    /* Full WPA/WPA2/WPA3 connection for Realtek chipsets. */
    pub fn connect(&mut self, ssid: &str, password: &str) -> Result<(), WifiError> {
        if self.state != WifiState::Ready && self.state != WifiState::HwReady && self.state != WifiState::FwLoaded {
            return Err(WifiError::InvalidState);
        }

        let target = self.scan_results.iter()
            .find(|r| r.ssid == ssid)
            .cloned()
            .ok_or(WifiError::NetworkNotFound)?;

        self.state = WifiState::Connecting;
        self.current_bssid = Some(target.bssid);
        self.current_security = target.security;
        self.current_channel = target.channel;

        crate::log::info!("rtlwifi: Connecting to '{}' ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            ssid, target.bssid[0], target.bssid[1], target.bssid[2],
            target.bssid[3], target.bssid[4], target.bssid[5]);

        self.set_channel(target.channel);

        match target.security {
            SecurityType::Open => self.connect_open(ssid, &target.bssid)?,
            SecurityType::WpaPsk | SecurityType::Wpa2Psk => self.connect_wpa2(ssid, password, &target.bssid)?,
            SecurityType::Wpa3Sae => self.connect_wpa3(ssid, password, &target.bssid)?,
            _ => {
                self.state = WifiState::Ready;
                return Err(WifiError::UnsupportedSecurity);
            }
        }

        Ok(())
    }

    fn connect_open(&mut self, ssid: &str, bssid: &[u8; 6]) -> Result<(), WifiError> {
        self.send_association_request(ssid, bssid)?;
        self.wait_for_association()?;
        self.current_ssid = Some(String::from(ssid));
        self.state = WifiState::Connected;
        crate::log::info!("rtlwifi: Connected to open network '{}'", ssid);
        Ok(())
    }

    fn connect_wpa2(&mut self, ssid: &str, password: &str, bssid: &[u8; 6]) -> Result<(), WifiError> {
        if password.is_empty() {
            return Err(WifiError::AuthenticationFailed);
        }

        let mut wpa_ctx = WpaContext::new(self.current_security, self.mac_address, *bssid);
        wpa_ctx.derive_pmk(password, ssid)?;
        crate::log::info!("rtlwifi: PMK derived");

        self.send_association_request(ssid, bssid)?;
        self.wait_for_association()?;
        crate::log::info!("rtlwifi: Associated, starting 4-way handshake");

        self.complete_wpa_handshake(&mut wpa_ctx)?;

        if let Some(tk) = wpa_ctx.get_temporal_key() {
            self.install_pairwise_key(tk)?;
            crate::log::info!("rtlwifi: Pairwise key installed");
        }

        self.current_ssid = Some(String::from(ssid));
        self.state = WifiState::Connected;
        crate::log::info!("rtlwifi: Connected to '{}' with WPA2-PSK", ssid);
        Ok(())
    }

    fn connect_wpa3(&mut self, ssid: &str, password: &str, bssid: &[u8; 6]) -> Result<(), WifiError> {
        if password.is_empty() {
            return Err(WifiError::AuthenticationFailed);
        }

        let mut wpa_ctx = WpaContext::new(SecurityType::Wpa3Sae, self.mac_address, *bssid);
        let mut sae_ctx = wpa_ctx.init_sae(password)?;

        sae_ctx.generate_commit()?;
        let our_commit = sae_ctx.our_commit.clone().ok_or(WifiError::InvalidState)?;
        self.send_sae_commit(&our_commit)?;

        let peer_commit = self.wait_for_sae_commit()?;
        let _ = wpa_ctx.process_sae_commit(&mut sae_ctx, &peer_commit)?;

        let our_confirm = sae_ctx.generate_confirm()?;
        self.send_sae_confirm(&our_confirm)?;

        let peer_confirm = self.wait_for_sae_confirm()?;
        wpa_ctx.process_sae_confirm(&mut sae_ctx, &peer_confirm)?;

        self.send_association_request(ssid, bssid)?;
        self.wait_for_association()?;
        self.complete_wpa_handshake(&mut wpa_ctx)?;

        if let Some(tk) = wpa_ctx.get_temporal_key() {
            self.install_pairwise_key(tk)?;
        }

        self.current_ssid = Some(String::from(ssid));
        self.state = WifiState::Connected;
        crate::log::info!("rtlwifi: Connected to '{}' with WPA3-SAE", ssid);
        Ok(())
    }

    fn complete_wpa_handshake(&mut self, wpa_ctx: &mut WpaContext) -> Result<(), WifiError> {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        let timeout_us = 10_000_000u64;

        while crate::arch::x86_64::time::tsc::elapsed_us() - start < timeout_us {
            let frames = self.process_rx_ring();
            for frame in frames {
                if frame.len() >= 14 {
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    if ethertype == 0x888E && frame.len() >= 18 {
                        let eapol_data = &frame[14..];
                        if let Ok(eapol) = parse_eapol_frame(eapol_data) {
                            if eapol.is_msg1() {
                                crate::log::info!("rtlwifi: Received EAPOL M1");
                                let msg2 = wpa_ctx.process_msg1(&eapol.nonce, eapol.replay_counter)?;
                                self.send_eapol(&msg2)?;
                                crate::log::info!("rtlwifi: Sent EAPOL M2");
                            } else if eapol.is_msg3() {
                                crate::log::info!("rtlwifi: Received EAPOL M3");
                                let msg4 = wpa_ctx.process_msg3(
                                    eapol_data, &eapol.key_data,
                                    &eapol.mic, eapol.replay_counter)?;
                                self.send_eapol(&msg4)?;
                                crate::log::info!("rtlwifi: Sent EAPOL M4");
                                if wpa_ctx.is_complete() {
                                    crate::log::info!("rtlwifi: 4-way handshake complete");
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
            self.delay_us(1000);
        }
        Err(WifiError::HandshakeTimeout)
    }

    fn send_eapol(&mut self, eapol_frame: &[u8]) -> Result<(), WifiError> {
        let bssid = self.current_bssid.ok_or(WifiError::NotConnected)?;
        let mut frame = Vec::with_capacity(24 + 8 + eapol_frame.len());

        frame.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&self.mac_address);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        frame.extend_from_slice(eapol_frame);

        self.transmit_raw(&frame)
    }

    fn install_pairwise_key(&mut self, tk: &[u8]) -> Result<(), WifiError> {
        if tk.len() < 16 {
            return Err(WifiError::InvalidKey);
        }

        for i in 0..4 {
            let word = u32::from_le_bytes([tk[i*4], tk[i*4+1], tk[i*4+2], tk[i*4+3]]);
            self.write32(regs::CAMWRITE + (i as u16) * 4, word);
        }

        let cam_cmd = (1u32 << 16) | (1u32 << 15);
        self.write32(regs::CAMCMD, cam_cmd);
        self.delay_us(100);
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }
        self.state = WifiState::Disconnecting;
        self.current_ssid = None;
        self.current_bssid = None;
        self.state = WifiState::Ready;
        crate::log::info!("rtlwifi: Disconnected");
        Ok(())
    }
}
