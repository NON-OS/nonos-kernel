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
Firmware loading for Realtek WiFi chipsets. Downloads firmware to device RAM
via MCUFWDL register, handles page-based transfer, and waits for MCU ready.
Also initializes RF and baseband after firmware is running.
*/

use super::super::super::error::WifiError;
use super::super::super::firmware::FirmwareInfo;
use super::super::types::WifiState;
use super::constants::*;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
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
}
