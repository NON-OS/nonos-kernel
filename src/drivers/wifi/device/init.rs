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

use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
use crate::drivers::pci::PciDevice;
use super::super::constants::*;
use super::super::dma::{RxQueue, TxQueue};
use super::super::error::WifiError;
use super::super::firmware::FirmwareLoader;
use super::super::pcie::PcieTransport;
use super::super::scan::SecurityType;
use super::intel::IntelWifiDevice;
use super::types::{WifiState, PowerConfig};

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
            current_security: SecurityType::Open,
            rssi: RSSI_INVALID,
            scan_results: Vec::new(),
            seq_num: AtomicU32::new(0),
            wpa_context: None,
            ccmp_context: None,
            power_config: PowerConfig::default(),
            power_save_enabled: false,
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

    pub(crate) fn read_mac_address(&mut self) -> Result<(), WifiError> {
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

    pub(crate) fn setup_queues(&mut self) -> Result<(), WifiError> {
        self.cmd_queue = Some(TxQueue::new(0, TFD_QUEUE_SIZE)?);
        self.rx_queue = Some(RxQueue::new(RX_QUEUE_SIZE)?);

        for i in 1..4 {
            self.tx_queues.push(TxQueue::new(i, TFD_QUEUE_SIZE)?);
        }

        self.configure_rx_queue()?;
        self.configure_tx_queues()?;

        Ok(())
    }

    pub(crate) fn configure_rx_queue(&mut self) -> Result<(), WifiError> {
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

    pub(crate) fn configure_tx_queues(&mut self) -> Result<(), WifiError> {
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

    pub(crate) fn timestamp() -> u64 {
        crate::arch::x86_64::time::tsc::elapsed_us()
    }
}
