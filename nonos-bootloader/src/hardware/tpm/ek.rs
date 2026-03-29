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

use alloc::vec::Vec;

use super::constants::*;
use super::state::TpmState;

const EK_HANDLE: u32 = 0x8101_0001;

impl TpmState {
    pub fn get_ek_public(&self) -> Result<Vec<u8>, &'static str> {
        if !self.initialized {
            return Err("TPM not initialized");
        }

        self.request_locality().map_err(|_| "locality request failed")?;

        let mut cmd = [0u8; 14];
        cmd[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        cmd[2..6].copy_from_slice(&14u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&0x0000_0173u32.to_be_bytes());
        cmd[10..14].copy_from_slice(&EK_HANDLE.to_be_bytes());

        self.send_read_public(&cmd)?;

        let response = self.receive_read_public()?;
        self.release_locality();

        Ok(response)
    }

    fn send_read_public(&self, cmd: &[u8]) -> Result<(), &'static str> {
        self.write_reg8(TPM_STS, TPM_STS_READY);
        for _ in 0..10000 {
            if (self.read_reg8(TPM_STS) & TPM_STS_READY) != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        for byte in cmd {
            self.write_reg8(TPM_DATA_FIFO, *byte);
        }

        self.write_reg8(TPM_STS, TPM_STS_GO);
        Ok(())
    }

    fn receive_read_public(&self) -> Result<Vec<u8>, &'static str> {
        for _ in 0..10000 {
            if (self.read_reg8(TPM_STS) & TPM_STS_DATA_AVAIL) != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        let mut response = Vec::with_capacity(512);
        for _ in 0..512 {
            if (self.read_reg8(TPM_STS) & TPM_STS_DATA_AVAIL) == 0 {
                break;
            }
            response.push(self.read_reg8(TPM_DATA_FIFO));
        }

        if response.len() < 10 {
            return Err("invalid TPM response");
        }

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err("TPM command failed");
        }

        Ok(response)
    }
}
