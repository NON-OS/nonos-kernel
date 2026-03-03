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

use super::super::error::I2cError;
use super::super::types::I2cSpeed;
use super::core::DesignWareI2c;
use super::registers::{
    DW_IC_COMP_TYPE_VALUE, IC_CLR_INTR, IC_COMP_PARAM_1, IC_COMP_TYPE, IC_CON, IC_CON_MASTER_MODE,
    IC_CON_RESTART_EN, IC_CON_SLAVE_DISABLE, IC_CON_SPEED_FS, IC_CON_SPEED_HS, IC_CON_SPEED_MASK,
    IC_CON_SPEED_SS, IC_FS_SCL_HCNT, IC_FS_SCL_LCNT, IC_FS_SPKLEN, IC_HS_SCL_HCNT, IC_HS_SCL_LCNT,
    IC_HS_SPKLEN, IC_INTR_MASK, IC_RX_TL, IC_SDA_HOLD, IC_SS_SCL_HCNT, IC_SS_SCL_LCNT, IC_TX_TL,
};

impl DesignWareI2c {
    pub fn init(&mut self) -> Result<(), I2cError> {
        let comp_type = self.read_reg(IC_COMP_TYPE);
        if comp_type != DW_IC_COMP_TYPE_VALUE {
            crate::log_warn!(
                "i2c: unexpected component type 0x{:08x}, expected 0x{:08x}",
                comp_type,
                DW_IC_COMP_TYPE_VALUE
            );
        }

        let comp_param = self.read_reg(IC_COMP_PARAM_1);
        self.tx_fifo_depth = ((comp_param >> 16) & 0xFF) + 1;
        self.rx_fifo_depth = ((comp_param >> 8) & 0xFF) + 1;

        self.disable()?;

        let con = IC_CON_MASTER_MODE
            | IC_CON_SLAVE_DISABLE
            | IC_CON_RESTART_EN
            | self.speed_to_con_bits();

        self.write_reg(IC_CON, con);

        self.configure_speed()?;

        self.write_reg(IC_INTR_MASK, 0);
        let _ = self.read_reg(IC_CLR_INTR);

        self.write_reg(IC_RX_TL, 0);
        self.write_reg(IC_TX_TL, self.tx_fifo_depth / 2);

        let sda_hold = self.calculate_sda_hold();
        self.write_reg(IC_SDA_HOLD, sda_hold);

        self.initialized.store(true, Ordering::SeqCst);

        crate::log::info!(
            "i2c: DesignWare controller at 0x{:x}, TX FIFO {}, RX FIFO {}",
            self.base,
            self.tx_fifo_depth,
            self.rx_fifo_depth
        );

        Ok(())
    }

    pub fn set_speed(&mut self, speed: I2cSpeed) -> Result<(), I2cError> {
        self.speed = speed;
        self.disable()?;

        let mut con = self.read_reg(IC_CON);
        con &= !IC_CON_SPEED_MASK;
        con |= self.speed_to_con_bits();
        self.write_reg(IC_CON, con);

        self.configure_speed()
    }

    fn configure_speed(&self) -> Result<(), I2cError> {
        let ic_clk = self.input_clock_hz;

        match self.speed {
            I2cSpeed::Standard => {
                let hcnt = (ic_clk / 100_000 / 2) - 7;
                let lcnt = (ic_clk / 100_000 / 2) - 1;
                self.write_reg(IC_SS_SCL_HCNT, hcnt.max(6));
                self.write_reg(IC_SS_SCL_LCNT, lcnt.max(8));
            }
            I2cSpeed::Fast | I2cSpeed::FastPlus => {
                let freq = self.speed.frequency_hz();
                let hcnt = (ic_clk / freq / 2) - 7;
                let lcnt = (ic_clk / freq / 2) - 1;
                self.write_reg(IC_FS_SCL_HCNT, hcnt.max(6));
                self.write_reg(IC_FS_SCL_LCNT, lcnt.max(8));

                let spklen = if self.speed == I2cSpeed::FastPlus {
                    ic_clk / 20_000_000
                } else {
                    ic_clk / 10_000_000
                };
                self.write_reg(IC_FS_SPKLEN, spklen.max(1));
            }
            I2cSpeed::High => {
                let hcnt = (ic_clk / 3_400_000 / 2) - 7;
                let lcnt = (ic_clk / 3_400_000 / 2) - 1;
                self.write_reg(IC_HS_SCL_HCNT, hcnt.max(6));
                self.write_reg(IC_HS_SCL_LCNT, lcnt.max(8));
                self.write_reg(IC_HS_SPKLEN, (ic_clk / 100_000_000).max(1));
            }
        }

        Ok(())
    }

    fn calculate_sda_hold(&self) -> u32 {
        let ic_clk_ns = 1_000_000_000 / self.input_clock_hz;
        let sda_hold_ns = 300;
        let sda_hold = sda_hold_ns / ic_clk_ns;
        sda_hold.max(1).min(0xFFFF)
    }

    fn speed_to_con_bits(&self) -> u32 {
        match self.speed {
            I2cSpeed::Standard => IC_CON_SPEED_SS,
            I2cSpeed::Fast | I2cSpeed::FastPlus => IC_CON_SPEED_FS,
            I2cSpeed::High => IC_CON_SPEED_HS,
        }
    }
}
