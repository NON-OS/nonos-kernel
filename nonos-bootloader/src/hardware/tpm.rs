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

use spin::Mutex;

pub const TPM_MMIO_BASE: u64 = 0xFED4_0000;
pub const TPM_MMIO_SIZE: usize = 0x5000;

pub const TPM_ACCESS: u32 = 0x0000;
pub const TPM_STS: u32 = 0x0018;
pub const TPM_DATA_FIFO: u32 = 0x0024;
pub const TPM_INTERFACE_ID: u32 = 0x0030;
pub const TPM_DID_VID: u32 = 0x0F00;

pub const TPM_ACCESS_VALID: u8 = 0x80;
pub const TPM_ACCESS_ACTIVE: u8 = 0x20;
pub const TPM_ACCESS_REQUEST: u8 = 0x02;

pub const TPM_STS_VALID: u8 = 0x80;
pub const TPM_STS_READY: u8 = 0x40;
pub const TPM_STS_GO: u8 = 0x20;
pub const TPM_STS_DATA_AVAIL: u8 = 0x10;
pub const TPM_STS_DATA_EXPECT: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    NotPresent,
    NotReady,
    Timeout,
    InvalidResponse,
    NvIndexNotFound,
    NvAccessDenied,
    NvSizeMismatch,
    CommandFailed(u32),
}

impl core::fmt::Display for TpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotPresent => write!(f, "TPM not present"),
            Self::NotReady => write!(f, "TPM not ready"),
            Self::Timeout => write!(f, "TPM timeout"),
            Self::InvalidResponse => write!(f, "invalid TPM response"),
            Self::NvIndexNotFound => write!(f, "NV index not found"),
            Self::NvAccessDenied => write!(f, "NV access denied"),
            Self::NvSizeMismatch => write!(f, "NV size mismatch"),
            Self::CommandFailed(rc) => write!(f, "TPM command failed: 0x{:X}", rc),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NvIndex {
    index: u32,
}

impl NvIndex {
    pub const fn new(index: u32) -> Self {
        Self { index }
    }

    pub fn raw(&self) -> u32 {
        self.index
    }
}

pub struct TpmState {
    base: u64,
    initialized: bool,
    version: u8,
}

impl TpmState {
    pub const fn new() -> Self {
        Self {
            base: TPM_MMIO_BASE,
            initialized: false,
            version: 0,
        }
    }

    fn read_reg8(&self, offset: u32) -> u8 {
        let addr = (self.base + offset as u64) as *const u8;
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write_reg8(&self, offset: u32, value: u8) {
        let addr = (self.base + offset as u64) as *mut u8;
        unsafe { core::ptr::write_volatile(addr, value) }
    }

    fn read_reg32(&self, offset: u32) -> u32 {
        let addr = (self.base + offset as u64) as *const u32;
        unsafe { core::ptr::read_volatile(addr) }
    }

    pub fn detect(&mut self) -> Result<bool, TpmError> {
        let did_vid = self.read_reg32(TPM_DID_VID);
        if did_vid == 0 || did_vid == 0xFFFF_FFFF {
            return Ok(false);
        }

        let interface_id = self.read_reg32(TPM_INTERFACE_ID);
        self.version = if (interface_id & 0x0F) == 0x00 {
            12
        } else {
            20
        };

        self.initialized = true;
        Ok(true)
    }

    pub fn request_locality(&self) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.write_reg8(TPM_ACCESS, TPM_ACCESS_REQUEST);

        for _ in 0..1000 {
            let access = self.read_reg8(TPM_ACCESS);
            if (access & TPM_ACCESS_ACTIVE) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(TpmError::Timeout)
    }

    pub fn release_locality(&self) {
        if self.initialized {
            self.write_reg8(TPM_ACCESS, TPM_ACCESS_ACTIVE);
        }
    }

    fn wait_for_status(&self, mask: u8, expected: u8) -> Result<(), TpmError> {
        for _ in 0..10000 {
            let sts = self.read_reg8(TPM_STS);
            if (sts & mask) == expected {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(TpmError::Timeout)
    }

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

pub static TPM: Mutex<TpmState> = Mutex::new(TpmState::new());

pub fn init_tpm() -> Result<bool, TpmError> {
    let mut tpm = TPM.lock();
    tpm.detect()
}

pub fn is_tpm_available() -> bool {
    let tpm = TPM.lock();
    tpm.initialized
}

pub fn nv_read(index: &NvIndex, buf: &mut [u8]) -> Result<usize, TpmError> {
    let tpm = TPM.lock();
    tpm.nv_read(index, buf)
}

pub fn nv_write(index: &NvIndex, data: &[u8]) -> Result<(), TpmError> {
    let tpm = TPM.lock();
    tpm.nv_write(index, data)
}

pub fn pcr_extend(pcr_index: u32, digest: &[u8; 32]) -> Result<(), TpmError> {
    let tpm = TPM.lock();
    tpm.pcr_extend(pcr_index, digest)
}
