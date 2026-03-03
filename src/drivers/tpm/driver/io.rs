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
use super::super::error::{TpmError, TpmResult};
use super::super::mmio::{mmio_read8, mmio_read32, mmio_write8, mmio_write32, spin_delay};
use super::core::TpmDriver;
use crate::drivers::security::rate_limiter::DriverOpType;

impl TpmDriver {
    pub(crate) fn send_command(&self, cmd: &[u8]) -> TpmResult<()> {
        self.wait_for_command_ready()?;

        unsafe {
            let mut sent = 0;

            while sent < cmd.len() {
                let burst = self.get_burst_count() as usize;
                if burst == 0 {
                    spin_delay(100);
                    continue;
                }

                let to_send = core::cmp::min(burst, cmd.len() - sent);
                for i in 0..to_send {
                    mmio_write8(self.base + regs::TPM_DATA_FIFO, cmd[sent + i]);
                }
                sent += to_send;
            }

            let status = mmio_read32(self.base + regs::TPM_STS);
            if (status & sts::TPM_STS_VALID) == 0 {
                return Err(TpmError::InvalidResponse);
            }

            mmio_write32(self.base + regs::TPM_STS, sts::TPM_STS_GO);
        }

        Ok(())
    }

    pub(crate) fn receive_response(&self, buf: &mut [u8]) -> TpmResult<usize> {
        unsafe {
            for _ in 0..RESPONSE_TIMEOUT_MS {
                let status = mmio_read32(self.base + regs::TPM_STS);

                if (status & sts::TPM_STS_DATA_AVAIL) != 0 {
                    break;
                }

                spin_delay(1000);
            }

            let status = mmio_read32(self.base + regs::TPM_STS);
            if (status & sts::TPM_STS_DATA_AVAIL) == 0 {
                return Err(TpmError::Timeout);
            }

            if buf.len() < 10 {
                return Err(TpmError::BufferTooSmall);
            }

            let mut received = 0;

            while received < 10 {
                let burst = self.get_burst_count();
                if burst == 0 {
                    spin_delay(100);
                    continue;
                }
                buf[received] = mmio_read8(self.base + regs::TPM_DATA_FIFO);
                received += 1;
            }

            let response_size =
                u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;

            if response_size > buf.len() {
                return Err(TpmError::BufferTooSmall);
            }

            while received < response_size {
                let burst = self.get_burst_count() as usize;
                if burst == 0 {
                    spin_delay(100);
                    continue;
                }

                let to_read = core::cmp::min(burst, response_size - received);
                for _ in 0..to_read {
                    if received >= buf.len() {
                        break;
                    }
                    buf[received] = mmio_read8(self.base + regs::TPM_DATA_FIFO);
                    received += 1;
                }
            }

            mmio_write32(self.base + regs::TPM_STS, sts::TPM_STS_COMMAND_READY);

            Ok(received)
        }
    }

    pub(crate) fn execute_command(&self, cmd: &[u8], response: &mut [u8]) -> TpmResult<usize> {
        if self.command_rate_limiter.check_rate(DriverOpType::ControlOp).is_err() {
            return Err(TpmError::RateLimitExceeded);
        }
        self.send_command(cmd)?;
        self.receive_response(response)
    }
}
