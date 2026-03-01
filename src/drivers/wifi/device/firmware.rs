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

use core::sync::atomic::Ordering;
use super::super::constants::*;
use super::super::error::WifiError;
use super::super::firmware::Firmware;
use super::intel::IntelWifiDevice;
use super::types::WifiState;

impl IntelWifiDevice {
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

    pub(crate) fn wait_for_alive(&mut self) -> Result<(), WifiError> {
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

    pub(crate) fn send_init_commands(&mut self) -> Result<(), WifiError> {
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
}
