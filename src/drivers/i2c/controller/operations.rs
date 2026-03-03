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
use super::super::types::I2cAbortSource;
use super::core::{timestamp, DesignWareI2c};
use super::registers::{
    IC_CLR_STOP_DET, IC_CLR_TX_ABRT, IC_DATA_CMD, IC_DATA_CMD_READ, IC_DATA_CMD_STOP,
    IC_INTR_STOP_DET, IC_INTR_TX_ABRT, IC_RAW_INTR_STAT, IC_RXFLR, IC_STATUS, IC_STATUS_RFNE,
    IC_TX_ABRT_SOURCE, IC_TXFLR,
};

impl DesignWareI2c {
    pub fn transfer(
        &self,
        addr: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<(), I2cError> {
        if !self.initialized.load(Ordering::Relaxed) {
            return Err(I2cError::NotInitialized);
        }

        self.wait_bus_not_busy()?;
        self.enable()?;

        self.set_target_address(addr)?;

        let write_len = write_data.len();
        let read_len = read_buf.len();
        let total = write_len + read_len;

        let mut write_idx = 0;
        let mut read_idx = 0;
        let mut cmd_idx = 0;

        while cmd_idx < total || read_idx < read_len {
            let raw_stat = self.read_reg(IC_RAW_INTR_STAT);
            if raw_stat & IC_INTR_TX_ABRT != 0 {
                let abort_src = self.read_reg(IC_TX_ABRT_SOURCE);
                let _ = self.read_reg(IC_CLR_TX_ABRT);
                self.disable()?;

                if let Some(src) = I2cAbortSource::from_bits(abort_src) {
                    match src {
                        I2cAbortSource::SevenBitAddrNack
                        | I2cAbortSource::TenBitAddr1Nack
                        | I2cAbortSource::TenBitAddr2Nack
                        | I2cAbortSource::TxDataNack => return Err(I2cError::Nack),
                        I2cAbortSource::ArbitrationLost => {
                            return Err(I2cError::ArbitrationLost)
                        }
                        _ => return Err(I2cError::TxAbort),
                    }
                }
                return Err(I2cError::TxAbort);
            }

            while read_idx < read_len && (self.read_reg(IC_STATUS) & IC_STATUS_RFNE) != 0 {
                read_buf[read_idx] = (self.read_reg(IC_DATA_CMD) & 0xFF) as u8;
                read_idx += 1;
            }

            if cmd_idx < total {
                let tx_limit = self.tx_fifo_depth - self.read_reg(IC_TXFLR);
                let rx_limit = self.rx_fifo_depth - self.read_reg(IC_RXFLR);

                while cmd_idx < total && tx_limit > 0 && rx_limit > 0 {
                    let is_last = cmd_idx == total - 1;

                    let mut cmd = if cmd_idx < write_len {
                        let c = write_data[write_idx] as u32;
                        write_idx += 1;
                        c
                    } else {
                        IC_DATA_CMD_READ
                    };

                    if is_last {
                        cmd |= IC_DATA_CMD_STOP;
                    }

                    self.write_reg(IC_DATA_CMD, cmd);
                    cmd_idx += 1;

                    if cmd_idx >= total {
                        break;
                    }
                }
            }

            if cmd_idx >= total && read_idx < read_len {
                self.wait_rx_data()?;
            }
        }

        self.wait_transfer_complete()?;
        self.disable()?;

        Ok(())
    }

    pub fn read(&self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), I2cError> {
        self.transfer(addr, &[reg], buf)
    }

    pub fn write(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), I2cError> {
        if data.is_empty() {
            return self.transfer(addr, &[reg], &mut []);
        }

        let mut write_buf = alloc::vec![0u8; data.len() + 1];
        write_buf[0] = reg;
        write_buf[1..].copy_from_slice(data);

        self.transfer(addr, &write_buf, &mut [])
    }

    pub fn write_read(
        &self,
        addr: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<(), I2cError> {
        self.transfer(addr, write_data, read_buf)
    }

    pub fn probe(&self, addr: u8) -> bool {
        if !self.initialized.load(Ordering::Relaxed) {
            return false;
        }

        if self.wait_bus_not_busy().is_err() {
            return false;
        }
        if self.enable().is_err() {
            return false;
        }
        if self.set_target_address(addr).is_err() {
            let _ = self.disable();
            return false;
        }

        self.write_reg(IC_DATA_CMD, IC_DATA_CMD_STOP);

        let start = timestamp();
        let mut found = false;

        while timestamp() - start < 10_000 {
            let raw_stat = self.read_reg(IC_RAW_INTR_STAT);

            if raw_stat & IC_INTR_TX_ABRT != 0 {
                let _ = self.read_reg(IC_CLR_TX_ABRT);
                break;
            }

            if raw_stat & IC_INTR_STOP_DET != 0 {
                let _ = self.read_reg(IC_CLR_STOP_DET);
                found = true;
                break;
            }

            core::hint::spin_loop();
        }

        let _ = self.disable();
        found
    }
}
