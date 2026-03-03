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

use super::super::error::I2cError;
use super::core::{timestamp, DesignWareI2c};
use super::registers::{
    IC_ENABLE, IC_ENABLE_ENABLE, IC_ENABLE_STATUS, IC_INTR_TX_ABRT, IC_RAW_INTR_STAT, IC_STATUS,
    IC_STATUS_MST_ACTIVITY, IC_STATUS_RFNE, IC_STATUS_TFE, IC_TAR, TIMEOUT_US,
};

impl DesignWareI2c {
    pub(super) fn enable(&self) -> Result<(), I2cError> {
        self.write_reg(IC_ENABLE, IC_ENABLE_ENABLE);

        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            if (self.read_reg(IC_ENABLE_STATUS) & 1) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(I2cError::Timeout)
    }

    pub(super) fn disable(&self) -> Result<(), I2cError> {
        self.write_reg(IC_ENABLE, 0);

        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            if (self.read_reg(IC_ENABLE_STATUS) & 1) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(I2cError::Timeout)
    }

    pub(super) fn set_target_address(&self, addr: u8) -> Result<(), I2cError> {
        let was_enabled = (self.read_reg(IC_ENABLE) & IC_ENABLE_ENABLE) != 0;

        if was_enabled {
            self.disable()?;
        }

        self.write_reg(IC_TAR, (addr & 0x7F) as u32);

        if was_enabled {
            self.enable()?;
        }

        Ok(())
    }

    pub(super) fn wait_bus_not_busy(&self) -> Result<(), I2cError> {
        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            let status = self.read_reg(IC_STATUS);
            if (status & IC_STATUS_MST_ACTIVITY) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(I2cError::BusBusy)
    }

    pub(super) fn wait_rx_data(&self) -> Result<(), I2cError> {
        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            if (self.read_reg(IC_STATUS) & IC_STATUS_RFNE) != 0 {
                return Ok(());
            }
            if (self.read_reg(IC_RAW_INTR_STAT) & IC_INTR_TX_ABRT) != 0 {
                return Err(I2cError::TxAbort);
            }
            core::hint::spin_loop();
        }
        Err(I2cError::Timeout)
    }

    pub(super) fn wait_transfer_complete(&self) -> Result<(), I2cError> {
        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            let status = self.read_reg(IC_STATUS);
            if (status & IC_STATUS_TFE) != 0 && (status & IC_STATUS_MST_ACTIVITY) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(I2cError::Timeout)
    }
}
