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

pub const NVRAM_VERSION_INDEX: u32 = 0x01C00002;
pub const NVRAM_BOOTLOADER_INDEX: u32 = 0x01C00003;
pub const DS_ROLLBACK: &str = "NONOS:ROLLBACK:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackError {
    KernelVersionTooOld { kernel: u64, minimum: u64 },
    BootloaderVersionTooOld { current: u64, minimum: u64 },
    NvramReadFailed,
    NvramWriteFailed,
    TpmNotAvailable,
    InvalidVersion,
}

impl core::fmt::Display for RollbackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KernelVersionTooOld { kernel, minimum } => {
                write!(f, "kernel {} < minimum {}", kernel, minimum)
            }
            Self::BootloaderVersionTooOld { current, minimum } => {
                write!(f, "bootloader {} < minimum {}", current, minimum)
            }
            Self::NvramReadFailed => write!(f, "NVRAM read failed"),
            Self::NvramWriteFailed => write!(f, "NVRAM write failed"),
            Self::TpmNotAvailable => write!(f, "TPM not available"),
            Self::InvalidVersion => write!(f, "invalid version"),
        }
    }
}

#[derive(Clone, Copy)]
pub struct VersionState {
    pub kernel_version: u64,
    pub bootloader_version: u64,
    pub minimum_kernel: u64,
    pub minimum_bootloader: u64,
    pub last_boot_timestamp: u64,
    pub boot_count: u64,
}

impl VersionState {
    pub const fn new() -> Self {
        Self {
            kernel_version: 0,
            bootloader_version: 0,
            minimum_kernel: 0,
            minimum_bootloader: 0,
            last_boot_timestamp: 0,
            boot_count: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..8].copy_from_slice(&self.kernel_version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.bootloader_version.to_le_bytes());
        buf[16..24].copy_from_slice(&self.minimum_kernel.to_le_bytes());
        buf[24..32].copy_from_slice(&self.minimum_bootloader.to_le_bytes());
        buf[32..40].copy_from_slice(&self.last_boot_timestamp.to_le_bytes());
        buf[40..48].copy_from_slice(&self.boot_count.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; 48]) -> Self {
        Self {
            kernel_version: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            bootloader_version: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            minimum_kernel: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            minimum_bootloader: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            last_boot_timestamp: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            boot_count: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ROLLBACK);
        hasher.update(&self.to_bytes());
        *hasher.finalize().as_bytes()
    }
}

pub struct AntiRollbackState {
    state: VersionState,
    initialized: bool,
    tpm_available: bool,
}

impl AntiRollbackState {
    pub const fn new() -> Self {
        Self {
            state: VersionState::new(),
            initialized: false,
            tpm_available: false,
        }
    }

    pub fn init(&mut self, tpm_available: bool) -> Result<(), RollbackError> {
        self.tpm_available = tpm_available;
        if tpm_available {
            match self.read_from_nvram() {
                Ok(state) => {
                    self.state = state;
                }
                Err(RollbackError::NvramReadFailed) => {
                    self.state = VersionState::new();
                }
                Err(e) => return Err(e),
            }
        }

        self.initialized = true;
        Ok(())
    }

    pub fn check_kernel_version(&self, kernel_version: u64) -> Result<(), RollbackError> {
        if !self.initialized && !self.tpm_available {
            return Err(RollbackError::TpmNotAvailable);
        }

        if kernel_version == 0 {
            return Err(RollbackError::InvalidVersion);
        }

        if self.initialized && kernel_version < self.state.minimum_kernel {
            return Err(RollbackError::KernelVersionTooOld {
                kernel: kernel_version,
                minimum: self.state.minimum_kernel,
            });
        }

        Ok(())
    }

    pub fn check_bootloader_version(&self, bootloader_version: u64) -> Result<(), RollbackError> {
        if !self.initialized && !self.tpm_available {
            return Err(RollbackError::TpmNotAvailable);
        }

        if bootloader_version == 0 {
            return Err(RollbackError::InvalidVersion);
        }

        if self.initialized && bootloader_version < self.state.minimum_bootloader {
            return Err(RollbackError::BootloaderVersionTooOld {
                current: bootloader_version,
                minimum: self.state.minimum_bootloader,
            });
        }

        Ok(())
    }

    pub fn update_kernel_version(
        &mut self,
        kernel_version: u64,
        timestamp: u64,
    ) -> Result<(), RollbackError> {
        if !self.initialized && !self.tpm_available {
            return Err(RollbackError::TpmNotAvailable);
        }

        self.check_kernel_version(kernel_version)?;

        if kernel_version > self.state.kernel_version {
            self.state.kernel_version = kernel_version;
        }

        if kernel_version > self.state.minimum_kernel {
            self.state.minimum_kernel = kernel_version;
        }

        self.state.last_boot_timestamp = timestamp;
        self.state.boot_count += 1;

        if self.tpm_available {
            self.write_to_nvram()?;
        }

        Ok(())
    }

    pub fn set_minimum_kernel_version(&mut self, version: u64) -> Result<(), RollbackError> {
        if version > self.state.minimum_kernel {
            self.state.minimum_kernel = version;
            if self.tpm_available {
                self.write_to_nvram()?;
            }
        }
        Ok(())
    }

    pub fn get_state(&self) -> &VersionState {
        &self.state
    }

    fn read_from_nvram(&self) -> Result<VersionState, RollbackError> {
        use crate::hardware::tpm::{nv_read, NvIndex};
        let index = NvIndex::new(NVRAM_VERSION_INDEX);
        let mut buf = [0u8; 48];
        match nv_read(&index, &mut buf) {
            Ok(48) => {
                let state = VersionState::from_bytes(&buf);
                let stored_hash = self.read_nvram_hash()?;
                let computed_hash = state.compute_hash();
                if !constant_time_eq_32(&stored_hash, &computed_hash) {
                    return Err(RollbackError::NvramReadFailed);
                }

                Ok(state)
            }
            Ok(_) => Err(RollbackError::NvramReadFailed),
            Err(_) => Err(RollbackError::NvramReadFailed),
        }
    }

    fn write_to_nvram(&self) -> Result<(), RollbackError> {
        use crate::hardware::tpm::{nv_write, NvIndex};
        let index = NvIndex::new(NVRAM_VERSION_INDEX);
        let data = self.state.to_bytes();

        nv_write(&index, &data).map_err(|_| RollbackError::NvramWriteFailed)?;

        let hash = self.state.compute_hash();
        let hash_index = NvIndex::new(NVRAM_VERSION_INDEX + 1);
        nv_write(&hash_index, &hash).map_err(|_| RollbackError::NvramWriteFailed)?;

        Ok(())
    }

    fn read_nvram_hash(&self) -> Result<[u8; 32], RollbackError> {
        use crate::hardware::tpm::{nv_read, NvIndex};
        let index = NvIndex::new(NVRAM_VERSION_INDEX + 1);
        let mut buf = [0u8; 32];
        match nv_read(&index, &mut buf) {
            Ok(32) => Ok(buf),
            _ => Err(RollbackError::NvramReadFailed),
        }
    }
}

#[inline(never)]
fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub static ANTI_ROLLBACK: Mutex<AntiRollbackState> = Mutex::new(AntiRollbackState::new());
pub fn init_anti_rollback(tpm_available: bool) -> Result<(), RollbackError> {
    let mut state = ANTI_ROLLBACK.lock();
    state.init(tpm_available)
}

pub fn check_kernel_version(version: u64) -> Result<(), RollbackError> {
    let state = ANTI_ROLLBACK.lock();
    state.check_kernel_version(version)
}

pub fn update_kernel_version(version: u64, timestamp: u64) -> Result<(), RollbackError> {
    let mut state = ANTI_ROLLBACK.lock();
    state.update_kernel_version(version, timestamp)
}

pub fn get_version_state() -> VersionState {
    let state = ANTI_ROLLBACK.lock();
    *state.get_state()
}
