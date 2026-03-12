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
use super::state::TpmState;
use super::types::{NvIndex, TpmError};

impl TpmState {
    pub fn send_command(&self, cmd: &[u8]) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.write_reg8(TPM_STS, TPM_STS_READY);
        self.wait_for_status(TPM_STS_READY, TPM_STS_READY)?;

        for byte in cmd {
            self.write_reg8(TPM_DATA_FIFO, *byte);
        }

        self.write_reg8(TPM_STS, TPM_STS_GO);
        Ok(())
    }

    pub fn receive_response(&self, buf: &mut [u8]) -> Result<usize, TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.wait_for_status(TPM_STS_DATA_AVAIL, TPM_STS_DATA_AVAIL)?;

        let mut received = 0;
        while received < buf.len() {
            let sts = self.read_reg8(TPM_STS);
            if (sts & TPM_STS_DATA_AVAIL) == 0 {
                break;
            }
            buf[received] = self.read_reg8(TPM_DATA_FIFO);
            received += 1;
        }

        self.write_reg8(TPM_STS, TPM_STS_READY);
        Ok(received)
    }

    pub fn nv_read(&self, index: &NvIndex, buf: &mut [u8]) -> Result<usize, TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.request_locality()?;

        let mut cmd = [0u8; 22];
        cmd[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        cmd[2..6].copy_from_slice(&22u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&0x0000_014Eu32.to_be_bytes());
        cmd[10..14].copy_from_slice(&index.raw().to_be_bytes());
        cmd[14..18].copy_from_slice(&index.raw().to_be_bytes());
        cmd[18..20].copy_from_slice(&(buf.len() as u16).to_be_bytes());
        cmd[20..22].copy_from_slice(&0u16.to_be_bytes());

        self.send_command(&cmd)?;

        let mut response = [0u8; 256];
        let len = self.receive_response(&mut response)?;

        self.release_locality();

        if len < 10 {
            return Err(TpmError::InvalidResponse);
        }

        let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        let data_len = u16::from_be_bytes(response[10..12].try_into().unwrap()) as usize;
        if data_len > buf.len() || 12 + data_len > len {
            return Err(TpmError::NvSizeMismatch);
        }

        buf[..data_len].copy_from_slice(&response[12..12 + data_len]);
        Ok(data_len)
    }

    pub fn nv_write(&self, index: &NvIndex, data: &[u8]) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.request_locality()?;

        let cmd_len = 22 + data.len();
        let mut cmd = [0u8; 256];
        cmd[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        cmd[2..6].copy_from_slice(&(cmd_len as u32).to_be_bytes());
        cmd[6..10].copy_from_slice(&0x0000_0137u32.to_be_bytes());
        cmd[10..14].copy_from_slice(&index.raw().to_be_bytes());
        cmd[14..18].copy_from_slice(&index.raw().to_be_bytes());
        cmd[18..20].copy_from_slice(&0u16.to_be_bytes());
        cmd[20..22].copy_from_slice(&(data.len() as u16).to_be_bytes());
        cmd[22..22 + data.len()].copy_from_slice(data);

        self.send_command(&cmd[..cmd_len])?;

        let mut response = [0u8; 32];
        let len = self.receive_response(&mut response)?;

        self.release_locality();

        if len < 10 {
            return Err(TpmError::InvalidResponse);
        }

        let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }

    pub fn pcr_extend(&self, pcr_index: u32, digest: &[u8; 32]) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.request_locality()?;

        let mut cmd = [0u8; 51];
        cmd[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        cmd[2..6].copy_from_slice(&51u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&0x0000_0182u32.to_be_bytes());
        cmd[10..14].copy_from_slice(&pcr_index.to_be_bytes());
        cmd[14..18].copy_from_slice(&1u32.to_be_bytes());
        cmd[18..19].copy_from_slice(&[0x0B]);
        cmd[19..51].copy_from_slice(digest);

        self.send_command(&cmd)?;

        let mut response = [0u8; 32];
        let len = self.receive_response(&mut response)?;

        self.release_locality();

        if len < 10 {
            return Err(TpmError::InvalidResponse);
        }

        let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }
}
