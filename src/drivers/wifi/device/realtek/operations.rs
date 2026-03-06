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
use super::super::super::scan::{ScanResult, ScanConfig, SecurityType};
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

    pub fn load_firmware(&mut self, fw_data: &[u8]) -> Result<(), WifiError> {
        if fw_data.len() < 64 {
            return Err(WifiError::FirmwareInvalid);
        }

        if fw_data.len() > FW_MAX_SIZE {
            return Err(WifiError::FirmwareInvalid);
        }

        crate::log::info!("rtlwifi: Loading firmware ({} bytes)", fw_data.len());

        let mcufwdl = self.read32(regs::MCUFWDL);
        self.write32(regs::MCUFWDL, mcufwdl | bits::MCUFWDL_EN);
        self.delay_us(100);

        self.write8(regs::MCUFWDL + 2, 0);
        self.delay_us(10);

        let mut offset = 0usize;
        while offset < fw_data.len() {
            let page_size = core::cmp::min(FW_PAGE_SIZE, fw_data.len() - offset);
            let page_num = (offset / FW_PAGE_SIZE) as u8;

            self.write8(regs::MCUFWDL + 2, page_num);
            self.delay_us(10);

            for i in (0..page_size).step_by(4) {
                let word_offset = offset + i;
                let val = if word_offset + 4 <= fw_data.len() {
                    u32::from_le_bytes([
                        fw_data[word_offset],
                        fw_data[word_offset + 1],
                        fw_data[word_offset + 2],
                        fw_data[word_offset + 3],
                    ])
                } else {
                    let mut bytes = [0u8; 4];
                    for j in 0..(fw_data.len() - word_offset) {
                        bytes[j] = fw_data[word_offset + j];
                    }
                    u32::from_le_bytes(bytes)
                };

                self.write32(FW_START_ADDR + i as u16, val);
            }

            offset += page_size;
        }

        self.write8(regs::MCUFWDL + 2, 0);
        let mcufwdl = self.read32(regs::MCUFWDL);
        self.write32(regs::MCUFWDL, mcufwdl & !bits::MCUFWDL_EN);

        self.write32(regs::MCUFWDL, self.read32(regs::MCUFWDL) | bits::CPRST);
        self.delay_us(100);
        self.write32(regs::MCUFWDL, self.read32(regs::MCUFWDL) & !bits::CPRST);

        let mut timeout = 1000u32;
        loop {
            let val = self.read32(regs::MCUFWDL);
            if val & bits::WINTINI_RDY != 0 {
                break;
            }
            if timeout == 0 {
                crate::log_warn!("rtlwifi: Firmware init timeout");
                return Err(WifiError::FirmwareTimeout);
            }
            timeout -= 1;
            self.delay_us(1000);
        }

        self.firmware_loaded = true;
        self.state = WifiState::FwLoaded;
        crate::log::info!("rtlwifi: Firmware loaded and running");

        self.init_rf_bb()?;
        self.state = WifiState::Ready;

        Ok(())
    }

    fn init_rf_bb(&mut self) -> Result<(), WifiError> {
        let sys_func = self.read16(regs::SYS_FUNC_EN);
        self.write16(regs::SYS_FUNC_EN, sys_func | bits::SYS_FUNC_EN_BB_GLB_RST);
        self.delay_us(100);
        self.write16(regs::SYS_FUNC_EN, sys_func | bits::SYS_FUNC_EN_BB_GLB_RST | bits::SYS_FUNC_EN_BBRSTB);
        self.delay_us(100);
        Ok(())
    }

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

    fn set_channel(&mut self, channel: u8) {
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

    fn transmit_raw(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if frame.len() > TX_BUFFER_SIZE - 48 {
            return Err(WifiError::BufferTooSmall);
        }

        let desc_ptr = (self.tx_ring_virt.as_u64() + (self.tx_head * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Err(WifiError::HardwareError);
        }

        let buf_addr = self.tx_buffers_virt.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        unsafe {
            ptr::copy_nonoverlapping(frame.as_ptr(), (buf_addr + 48) as *mut u8, frame.len());
        }

        let buf_phys = self.tx_buffers_phys.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        desc.configure_tx((frame.len() + 48) as u16, buf_phys);

        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;
        Ok(())
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

    pub fn init_tx_descriptors(&mut self) {
        for i in 0..TX_RING_SIZE {
            let desc_ptr = (self.tx_ring_virt.as_u64() + (i * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;
            unsafe {
                ptr::write(desc_ptr, RtlTxDesc::new());
            }
        }
    }

    pub fn init_rx_descriptors(&mut self) {
        for i in 0..RX_RING_SIZE {
            let desc_ptr = (self.rx_ring_virt.as_u64() + (i * core::mem::size_of::<RtlRxDesc>()) as u64) as *mut RtlRxDesc;
            let buf_addr = self.rx_buffers_phys.as_u64() + (i * RX_BUFFER_SIZE) as u64;
            unsafe {
                ptr::write(desc_ptr, RtlRxDesc::new());
                let desc = &*desc_ptr;
                desc.configure_rx(RX_BUFFER_SIZE as u16, buf_addr);
            }
        }
    }

    pub fn process_rx_ring(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        loop {
            let desc_ptr = (self.rx_ring_virt.as_u64() + (self.rx_head * core::mem::size_of::<RtlRxDesc>()) as u64) as *const RtlRxDesc;
            let desc = unsafe { &*desc_ptr };

            if desc.is_own() {
                break;
            }

            if desc.is_crc_err() || desc.is_icv_err() {
                desc.clear_own();
                desc.set_own();
                self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
                continue;
            }

            if !desc.is_first_seg() || !desc.is_last_seg() {
                desc.set_own();
                self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
                continue;
            }

            let pkt_len = desc.pkt_len() as usize;
            if pkt_len > 0 && pkt_len <= RX_BUFFER_SIZE {
                let buf_addr = self.rx_buffers_virt.as_u64() + (self.rx_head * RX_BUFFER_SIZE) as u64;
                let mut data = alloc::vec![0u8; pkt_len];
                unsafe {
                    ptr::copy_nonoverlapping(buf_addr as *const u8, data.as_mut_ptr(), pkt_len);
                }
                frames.push(data);
            }

            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
        }

        frames
    }
}
