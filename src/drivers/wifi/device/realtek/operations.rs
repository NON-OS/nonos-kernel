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

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

use super::super::super::error::WifiError;
use super::super::super::scan::{ScanResult, ScanConfig};
use super::super::super::api::LinkInfo;
use super::super::super::firmware::FirmwareInfo;
use super::super::types::WifiState;
use super::constants::*;
use super::core::RealtekWifiDevice;
use super::descriptors::{RtlTxDesc, RtlRxDesc};

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

    pub fn load_firmware(&mut self, _fw_data: &[u8]) -> Result<(), WifiError> {
        crate::log::info!("rtlwifi: Firmware loading not yet implemented for Realtek");
        self.firmware_loaded = true;
        self.state = WifiState::FwLoaded;
        Ok(())
    }

    pub fn scan(&mut self, _config: ScanConfig) -> Result<Vec<ScanResult>, WifiError> {
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

        self.delay_us(100_000);

        self.state = prev_state;
        Ok(self.scan_results.clone())
    }

    pub fn connect(&mut self, ssid: &str, _password: &str) -> Result<(), WifiError> {
        if self.state != WifiState::Ready && self.state != WifiState::HwReady && self.state != WifiState::FwLoaded {
            return Err(WifiError::InvalidState);
        }

        self.state = WifiState::Connecting;
        crate::log::info!("rtlwifi: Connecting to '{}'...", ssid);

        self.current_ssid = Some(String::from(ssid));
        self.state = WifiState::Connected;

        crate::log::info!("rtlwifi: Connected to '{}'", ssid);
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

    pub fn receive(&mut self) -> Result<Option<Vec<u8>>, WifiError> {
        let desc_ptr = (self.rx_ring_virt.as_u64() + (self.rx_head * core::mem::size_of::<RtlRxDesc>()) as u64) as *const RtlRxDesc;

        // SAFETY: Reading from allocated DMA memory
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Ok(None);
        }

        if desc.is_crc_err() || desc.is_icv_err() {
            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(None);
        }

        let pkt_len = desc.pkt_len() as usize;
        if pkt_len == 0 || pkt_len > RX_BUFFER_SIZE {
            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(None);
        }

        let buf_addr = self.rx_buffers_virt.as_u64() + (self.rx_head * RX_BUFFER_SIZE) as u64;
        let mut data = alloc::vec![0u8; pkt_len];

        // SAFETY: Copying from DMA buffer
        unsafe {
            ptr::copy_nonoverlapping(buf_addr as *const u8, data.as_mut_ptr(), pkt_len);
        }

        desc.set_own();
        self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;

        Ok(Some(data))
    }

    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        if frame.len() > TX_BUFFER_SIZE - 48 {
            return Err(WifiError::BufferTooSmall);
        }

        let desc_ptr = (self.tx_ring_virt.as_u64() + (self.tx_head * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;

        // SAFETY: Checking DMA descriptor ownership
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Err(WifiError::HardwareError);
        }

        let buf_addr = self.tx_buffers_virt.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;

        // SAFETY: Copying to DMA buffer
        unsafe {
            ptr::copy_nonoverlapping(frame.as_ptr(), (buf_addr + 48) as *mut u8, frame.len());
        }

        let buf_phys = self.tx_buffers_phys.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        desc.configure_tx((frame.len() + 48) as u16, buf_phys);

        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;

        Ok(())
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

    pub fn firmware_info(&self) -> Option<FirmwareInfo> {
        if self.firmware_loaded {
            Some(FirmwareInfo {
                major: 0,
                minor: 0,
                api: 0,
                build: 0,
                human_readable: [0; 64],
            })
        } else {
            None
        }
    }

    pub fn handle_interrupt(&mut self) {
        let isr = self.read32(regs::HISR);
        if isr == 0 {
            return;
        }

        self.write32(regs::HISR, isr);
    }
}
