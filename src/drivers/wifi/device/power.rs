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

use super::super::constants::*;
use super::super::error::WifiError;
use super::intel::IntelWifiDevice;
use super::types::{WifiState, PowerSaveMode, PowerConfig};

impl IntelWifiDevice {
    pub fn set_power_save(&mut self, mode: PowerSaveMode) -> Result<(), WifiError> {
        if self.state != WifiState::Connected && mode != PowerSaveMode::Disabled {
            return Err(WifiError::InvalidState);
        }

        self.power_config.mode = mode;
        self.send_power_table_cmd()?;

        match mode {
            PowerSaveMode::Disabled => {
                self.power_save_enabled = false;
                self.send_null_data_frame(false)?;
            }
            _ => {
                self.power_save_enabled = true;
                self.send_null_data_frame(true)?;
            }
        }

        crate::log::info!(
            "iwlwifi: Power save mode set to {:?}",
            mode
        );

        Ok(())
    }

    pub fn configure_power_save(&mut self, config: PowerConfig) -> Result<(), WifiError> {
        self.power_config = config;

        if self.state == WifiState::Connected {
            self.send_power_table_cmd()?;
            if config.tx_power_reduction_dbm > 0 {
                self.send_tx_power_cmd()?;
            }
        }

        Ok(())
    }

    pub fn get_power_config(&self) -> &PowerConfig {
        &self.power_config
    }

    pub fn is_power_save_enabled(&self) -> bool {
        self.power_save_enabled
    }

    pub(crate) fn send_power_table_cmd(&mut self) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 64];

        let flags = match self.power_config.mode {
            PowerSaveMode::Disabled => 0x00u16,
            PowerSaveMode::LightSleep => 0x01,
            PowerSaveMode::DeepSleep => 0x03,
            PowerSaveMode::UltraLowPower => 0x07,
        };

        cmd_data[0..2].copy_from_slice(&flags.to_le_bytes());
        cmd_data[2..4].copy_from_slice(&self.power_config.listen_interval.to_le_bytes());
        cmd_data[4] = self.power_config.dtim_period;
        cmd_data[5] = if self.power_config.skip_dtim { 1 } else { 0 };
        cmd_data[6] = if self.power_config.rx_chain_power_save { 1 } else { 0 };

        let keep_alive_sec: u16 = match self.power_config.mode {
            PowerSaveMode::Disabled => 0,
            PowerSaveMode::LightSleep => 25,
            PowerSaveMode::DeepSleep => 50,
            PowerSaveMode::UltraLowPower => 100,
        };
        cmd_data[8..10].copy_from_slice(&keep_alive_sec.to_le_bytes());

        let rx_timeout: u32 = match self.power_config.mode {
            PowerSaveMode::Disabled => 0,
            PowerSaveMode::LightSleep => 100,
            PowerSaveMode::DeepSleep => 200,
            PowerSaveMode::UltraLowPower => 500,
        };
        cmd_data[12..16].copy_from_slice(&rx_timeout.to_le_bytes());

        let tx_timeout: u32 = match self.power_config.mode {
            PowerSaveMode::Disabled => 0,
            PowerSaveMode::LightSleep => 100,
            PowerSaveMode::DeepSleep => 200,
            PowerSaveMode::UltraLowPower => 300,
        };
        cmd_data[16..20].copy_from_slice(&tx_timeout.to_le_bytes());

        let sleep_interval: u16 = match self.power_config.mode {
            PowerSaveMode::Disabled => 0,
            PowerSaveMode::LightSleep => 10,
            PowerSaveMode::DeepSleep => 50,
            PowerSaveMode::UltraLowPower => 200,
        };
        cmd_data[20..22].copy_from_slice(&sleep_interval.to_le_bytes());

        self.send_cmd(cmd::MAC_PM_POWER_TABLE, &cmd_data)
    }

    pub(crate) fn send_tx_power_cmd(&mut self) -> Result<(), WifiError> {
        let mut cmd_data = [0u8; 16];

        let reduction = self.power_config.tx_power_reduction_dbm.min(20);
        cmd_data[0] = 1;
        cmd_data[4] = reduction;

        self.send_cmd(cmd::REDUCE_TX_POWER_CMD, &cmd_data)
    }

    pub(crate) fn send_null_data_frame(&mut self, power_mgmt: bool) -> Result<(), WifiError> {
        let bssid = self.current_bssid.ok_or(WifiError::NotConnected)?;

        let mut frame = alloc::vec::Vec::with_capacity(24);

        let frame_control: u16 = if power_mgmt {
            0x4801
        } else {
            0x4001
        };
        frame.extend_from_slice(&frame_control.to_le_bytes());

        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&self.mac_address);
        frame.extend_from_slice(&bssid);

        let seq = self.seq_num.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u16;
        frame.extend_from_slice(&((seq << 4) as u16).to_le_bytes());

        self.transmit_raw(&frame)
    }

    pub fn wake_from_sleep(&mut self) -> Result<(), WifiError> {
        if !self.power_save_enabled {
            return Ok(());
        }

        self.trans.grab_nic_access()?;

        let gp_cntrl = self.trans.regs.read32(csr::GP_CNTRL);
        self.trans.regs.write32(
            csr::GP_CNTRL,
            gp_cntrl | csr_bits::GP_CNTRL_MAC_ACCESS_REQ
        );

        let start = Self::timestamp();
        while Self::timestamp() - start < NIC_ACCESS_TIMEOUT_US {
            let val = self.trans.regs.read32(csr::GP_CNTRL);
            if (val & csr_bits::GP_CNTRL_MAC_CLOCK_READY) != 0 {
                self.trans.release_nic_access();
                return Ok(());
            }
            core::hint::spin_loop();
        }

        self.trans.release_nic_access();
        Err(WifiError::Timeout)
    }

    pub fn enter_sleep(&mut self) -> Result<(), WifiError> {
        if !self.power_save_enabled || self.power_config.mode == PowerSaveMode::Disabled {
            return Ok(());
        }

        self.send_null_data_frame(true)?;

        self.trans.grab_nic_access()?;

        let gp_cntrl = self.trans.regs.read32(csr::GP_CNTRL);
        self.trans.regs.write32(
            csr::GP_CNTRL,
            gp_cntrl | csr_bits::GP_CNTRL_REG_FLAG_GOING_TO_SLEEP
        );

        self.trans.release_nic_access();

        Ok(())
    }
}
