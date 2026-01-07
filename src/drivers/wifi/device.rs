// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;
use super::dma::{RxQueue, TxQueue};
use super::error::WifiError;
use super::firmware::{Firmware, FirmwareInfo, FirmwareLoader};
use super::pcie::PcieTransport;
use super::scan::{ScanConfig, ScanResult};
use super::LinkInfo;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::drivers::pci::PciDevice;
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiState {
    Uninitialized,
    HwReady,
    FwLoaded,
    Ready,
    Scanning,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

pub struct IntelWifiDevice {
    trans: PcieTransport,
    state: WifiState,
    firmware: Option<Firmware>,
    fw_loader: FirmwareLoader,
    tx_queues: Vec<TxQueue>,
    rx_queue: Option<RxQueue>,
    cmd_queue: Option<TxQueue>,
    device_id: u16,
    mac_address: [u8; 6],
    current_ssid: Option<String>,
    current_bssid: Option<[u8; 6]>,
    current_channel: u8,
    rssi: i8,
    scan_results: Vec<ScanResult>,
    seq_num: AtomicU32,
}

impl IntelWifiDevice {
    pub fn new(pci_device: PciDevice) -> Result<Self, WifiError> {
        let device_id = pci_device.device_id_value();
        let trans = PcieTransport::new(pci_device)?;

        if trans.is_rf_kill() {
            crate::log_warn!("iwlwifi: RF kill switch is active");
            return Err(WifiError::RfKill);
        }

        let mut dev = Self {
            trans,
            state: WifiState::HwReady,
            firmware: None,
            fw_loader: FirmwareLoader::new(),
            tx_queues: Vec::new(),
            rx_queue: None,
            cmd_queue: None,
            device_id,
            mac_address: [0; 6],
            current_ssid: None,
            current_bssid: None,
            current_channel: 0,
            rssi: RSSI_INVALID,
            scan_results: Vec::new(),
            seq_num: AtomicU32::new(0),
        };

        dev.read_mac_address()?;
        dev.setup_queues()?;

        crate::log::info!(
            "iwlwifi: Device ready, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dev.mac_address[0],
            dev.mac_address[1],
            dev.mac_address[2],
            dev.mac_address[3],
            dev.mac_address[4],
            dev.mac_address[5]
        );

        Ok(dev)
    }

    fn read_mac_address(&mut self) -> Result<(), WifiError> {
        self.trans.grab_nic_access()?;
        let word0 = self.trans.regs.read_prph(NVM_MAC_ADDR);
        let word1 = self.trans.regs.read_prph(NVM_MAC_ADDR + 4);
        self.trans.release_nic_access();
        self.mac_address[0] = (word0 & 0xFF) as u8;
        self.mac_address[1] = ((word0 >> 8) & 0xFF) as u8;
        self.mac_address[2] = ((word0 >> 16) & 0xFF) as u8;
        self.mac_address[3] = ((word0 >> 24) & 0xFF) as u8;
        self.mac_address[4] = (word1 & 0xFF) as u8;
        self.mac_address[5] = ((word1 >> 8) & 0xFF) as u8;
        if self.mac_address == [0xFF; 6] || self.mac_address == [0; 6] {
            self.mac_address = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        }

        Ok(())
    }

    fn setup_queues(&mut self) -> Result<(), WifiError> {
        self.cmd_queue = Some(TxQueue::new(0, TFD_QUEUE_SIZE)?);
        self.rx_queue = Some(RxQueue::new(RX_QUEUE_SIZE)?);

        for i in 1..4 {
            self.tx_queues.push(TxQueue::new(i, TFD_QUEUE_SIZE)?);
        }

        self.configure_rx_queue()?;
        self.configure_tx_queues()?;

        Ok(())
    }

    fn configure_rx_queue(&mut self) -> Result<(), WifiError> {
        let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;

        self.trans.grab_nic_access()?;

        self.trans.regs.write32(
            fh::RSCSR_CHNL0_RBDCB_BASE_REG,
            rx_queue.bd_phys().as_u64() as u32,
        );
        self.trans.regs.write32(
            fh::RSCSR_CHNL0_STTS_WPTR_REG,
            rx_queue.stts_phys().as_u64() as u32,
        );

        let rx_config = fh::RCSR_RX_CONFIG_REG_IRQ_DEST_HOST
            | fh::RCSR_RX_CONFIG_REG_RB_SIZE_4K
            | fh::RCSR_RX_CONFIG_REG_RBDCB_SIZE_8;

        self.trans
            .regs
            .write32(fh::RCSR_CHNL0_CONFIG_REG, rx_config);

        self.trans.release_nic_access();
        Ok(())
    }

    fn configure_tx_queues(&mut self) -> Result<(), WifiError> {
        self.trans.grab_nic_access()?;

        if let Some(ref cmd_queue) = self.cmd_queue {
            let base = fh::TCSR_CHNL_TX_CONFIG_REG + (0 * 0x20);
            self.trans
                .regs
                .write32(base, cmd_queue.phys_addr().as_u64() as u32);
            self.trans.regs.write32(
                base + 0x04,
                fh::TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE,
            );
        }

        for (i, tx_queue) in self.tx_queues.iter().enumerate() {
            let base = fh::TCSR_CHNL_TX_CONFIG_REG + ((i as u32 + 1) * 0x20);
            self.trans
                .regs
                .write32(base, tx_queue.phys_addr().as_u64() as u32);
            self.trans.regs.write32(
                base + 0x04,
                fh::TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE,
            );
        }

        self.trans.release_nic_access();
        Ok(())
    }

    pub fn load_firmware(&mut self, fw_data: &[u8]) -> Result<(), WifiError> {
        let fw = Firmware::parse(fw_data)?;
        self.fw_loader.load(&mut self.trans, &fw)?;

        self.firmware = Some(fw);
        self.state = WifiState::FwLoaded;

        self.wait_for_alive()?;
        self.send_init_commands()?;

        self.state = WifiState::Ready;
        Ok(())
    }

    fn wait_for_alive(&mut self) -> Result<(), WifiError> {
        let timeout_us = ALIVE_TIMEOUT_MS * 1000;
        let start = Self::timestamp();

        while Self::timestamp() - start < timeout_us {
            let int = self.trans.ack_interrupts();
            if int & csr_bits::INT_BIT_ALIVE != 0 {
                crate::log::info!("iwlwifi: Received ALIVE notification");
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(WifiError::Timeout)
    }

    fn send_init_commands(&mut self) -> Result<(), WifiError> {
        self.send_phy_db_cmd()?;
        self.send_nvm_access_cmd()?;
        self.send_phy_cfg_cmd()?;

        Ok(())
    }

    fn send_phy_db_cmd(&mut self) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 8];
        cmd_data[0] = 0;
        self.send_cmd(cmd::PHY_DB_CMD, &cmd_data)
    }

    fn send_nvm_access_cmd(&mut self) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 12];
        cmd_data[0] = 0;
        cmd_data[1] = 0;
        cmd_data[2] = 1;
        self.send_cmd(cmd::NVM_ACCESS_CMD, &cmd_data)
    }

    fn send_phy_cfg_cmd(&mut self) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 16];
        cmd_data[0] = 1;
        cmd_data[1] = 1;
        cmd_data[8] = 0x1F;
        cmd_data[9] = 0x00;
        self.send_cmd(cmd::PHY_CONTEXT_CMD, &cmd_data)
    }

    pub fn send_cmd(&mut self, cmd_id: u32, data: &[u8]) -> Result<(), WifiError> {
        let cmd_queue = self.cmd_queue.as_mut().ok_or(WifiError::InvalidState)?;

        if data.len() > MAX_CMD_PAYLOAD_SIZE {
            return Err(WifiError::InvalidParameter);
        }

        let seq = self.seq_num.fetch_add(1, Ordering::Relaxed);

        let mut cmd_buf = [0u8; MAX_CMD_PAYLOAD_SIZE + 16];

        cmd_buf[0..4].copy_from_slice(&cmd_id.to_le_bytes());
        cmd_buf[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        cmd_buf[8..12].copy_from_slice(&seq.to_le_bytes());
        cmd_buf[12] = 0;
        cmd_buf[13] = 0;
        cmd_buf[14] = 0;
        cmd_buf[15] = 0;

        cmd_buf[16..16 + data.len()].copy_from_slice(data);

        let total_len = 16 + data.len();
        cmd_queue.enqueue(&cmd_buf[..total_len])?;

        self.trans.grab_nic_access()?;
        let write_ptr_reg = TX_QUEUE_WRITE_PTR_BASE + (cmd_queue.id() as u32 * 4);
        self.trans
            .regs
            .write32(write_ptr_reg, cmd_queue.write_ptr());
        self.trans.release_nic_access();

        Ok(())
    }

    pub fn scan(&mut self, config: ScanConfig) -> Result<Vec<ScanResult>, WifiError> {
        if self.state != WifiState::Ready && self.state != WifiState::Connected {
            return Err(WifiError::InvalidState);
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

    fn build_scan_cmd(&self, config: &ScanConfig) -> Vec<u8> {
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

    fn process_rx(&mut self) -> Result<(), WifiError> {
        let (mut read_ptr, hw_ptr) = {
            let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;
            (rx_queue.write_ptr(), rx_queue.hw_read_ptr())
        };

        while read_ptr != hw_ptr {
            let packet_data = {
                let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;
                rx_queue.get_buffer(read_ptr as usize).to_vec()
            };

            self.handle_rx_packet(&packet_data)?;

            {
                let rx_queue = self.rx_queue.as_mut().ok_or(WifiError::InvalidState)?;
                rx_queue.replenish(read_ptr as usize)?;
            }

            read_ptr = (read_ptr + 1) % RX_QUEUE_SIZE as u32;
        }

        {
            let rx_queue = self.rx_queue.as_mut().ok_or(WifiError::InvalidState)?;
            rx_queue.set_write_ptr(read_ptr);
        }

        self.trans.grab_nic_access()?;
        self.trans.regs.write32(fh::RSCSR_CHNL0_WPTR, read_ptr);
        self.trans.release_nic_access();

        Ok(())
    }

    fn handle_rx_packet(&mut self, buf: &[u8]) -> Result<(), WifiError> {
        if buf.len() < 4 {
            return Ok(());
        }

        let cmd_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

        match cmd_id {
            cmd::SCAN_COMPLETE_UMAC => {
                self.state = WifiState::Ready;
            }
            cmd::SCAN_ITERATION_COMPLETE_UMAC => {
                if buf.len() >= 64 {
                    let result = self.parse_scan_result(&buf[8..])?;
                    self.scan_results.push(result);
                }
            }
            cmd::BEACON_NOTIFICATION => {
                if self.state == WifiState::Connected && buf.len() >= 16 {
                    self.rssi = buf[12] as i8;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn parse_scan_result(&self, data: &[u8]) -> Result<ScanResult, WifiError> {
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
            0 => super::scan::SecurityType::Open,
            1 => super::scan::SecurityType::Wep,
            2 => super::scan::SecurityType::WpaPsk,
            3 => super::scan::SecurityType::Wpa2Psk,
            4 => super::scan::SecurityType::Wpa3Sae,
            _ => super::scan::SecurityType::Unknown,
        };

        Ok(ScanResult {
            ssid,
            bssid,
            channel,
            rssi,
            security: security_type,
        })
    }

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

        self.send_mac_context_cmd(&target)?;
        self.send_time_event_cmd()?;
        self.send_binding_cmd(&target)?;

        let auth_cmd = self.build_auth_cmd(&target, password);
        self.send_cmd(cmd::ADD_STA, &auth_cmd)?;

        let timeout_us = CONNECT_TIMEOUT_MS * 1000;
        let start = Self::timestamp();

        while Self::timestamp() - start < timeout_us {
            self.process_rx()?;

            let int = self.trans.ack_interrupts();
            if int != 0 {
                break;
            }

            core::hint::spin_loop();
        }

        self.current_ssid = Some(ssid.to_string());
        self.current_bssid = Some(target.bssid);
        self.current_channel = target.channel;
        self.rssi = target.rssi;
        self.state = WifiState::Connected;

        crate::log::info!(
            "iwlwifi: Connected to {} on channel {}",
            ssid,
            target.channel
        );
        Ok(())
    }

    fn send_mac_context_cmd(&mut self, target: &ScanResult) -> Result<(), WifiError> {
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

    fn send_time_event_cmd(&mut self) -> Result<(), WifiError> {
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

    fn send_binding_cmd(&mut self, target: &ScanResult) -> Result<(), WifiError> {
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

    fn build_auth_cmd(&self, target: &ScanResult, password: &str) -> Vec<u8> {
        let mut cmd = vec![0u8; AUTH_CMD_SIZE];

        cmd[0..6].copy_from_slice(&target.bssid);
        cmd[6] = 0x01;

        let ssid_bytes = target.ssid.as_bytes();
        let ssid_len = ssid_bytes.len().min(32);
        cmd[8] = ssid_len as u8;
        cmd[9..9 + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);

        let pwd_bytes = password.as_bytes();
        let pwd_len = pwd_bytes.len().min(64);
        cmd[48] = pwd_len as u8;
        cmd[49..49 + pwd_len].copy_from_slice(&pwd_bytes[..pwd_len]);

        cmd
    }

    pub fn disconnect(&mut self) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Ok(());
        }

        self.state = WifiState::Disconnecting;

        let remove_cmd = [0u8; 8];
        self.send_cmd(cmd::REMOVE_STA, &remove_cmd)?;

        self.current_ssid = None;
        self.current_bssid = None;
        self.current_channel = 0;
        self.rssi = RSSI_INVALID;
        self.state = WifiState::Ready;

        crate::log::info!("iwlwifi: Disconnected");
        Ok(())
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        if self.tx_queues.is_empty() {
            return Err(WifiError::InvalidState);
        }

        let tx_queue = &mut self.tx_queues[0];
        tx_queue.enqueue(data)?;

        self.trans.grab_nic_access()?;
        let write_ptr_reg = TX_QUEUE_WRITE_PTR_BASE + (tx_queue.id() as u32 * 4);
        self.trans
            .regs
            .write32(write_ptr_reg, tx_queue.write_ptr());
        self.trans.release_nic_access();

        Ok(())
    }

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
        let rate = super::tx::select_tx_rate(self.rssi, is_5ghz);

        Some(LinkInfo {
            ssid: self.current_ssid.clone()?,
            bssid: self.current_bssid?,
            channel: self.current_channel,
            rssi: self.rssi,
            tx_rate: rate,
            rx_rate: rate,
        })
    }

    fn timestamp() -> u64 {
        crate::arch::x86_64::time::tsc::elapsed_us()
    }
}
