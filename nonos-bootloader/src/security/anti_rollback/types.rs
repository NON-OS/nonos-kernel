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
        let kernel_version = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        let bootloader_version = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let minimum_kernel = u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
        let minimum_bootloader = u64::from_le_bytes([buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]]);
        let last_boot_timestamp = u64::from_le_bytes([buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39]]);
        let boot_count = u64::from_le_bytes([buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47]]);
        Self {
            kernel_version,
            bootloader_version,
            minimum_kernel,
            minimum_bootloader,
            last_boot_timestamp,
            boot_count,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ROLLBACK);
        hasher.update(&self.to_bytes());
        *hasher.finalize().as_bytes()
    }
}
