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


use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciError {
    Bar5NotConfigured,
    HbaResetTimeout,
    BiosHandoffTimeout,
    PortCmdListStopTimeout,
    PortFisStopTimeout,
    ZeroSectorCapacity,
    PortNotInitialized,
    LbaRangeExceeded,
    LbaOverflow,
    InvalidBufferSize,
    BufferAddressOverflow,
    BufferInCriticalRegion,
    BufferNotAligned,
    NoFreeSlots,
    CommandFailed,
    CommandTimeout,
    TrimNotSupported,
    TrimRateLimitExceeded,
    SecureEraseNotSupported,
    CipherNotInitialized,
    PortDmaNotInitialized,
    DmaAllocationFailed,
    PortResetFailed,
    NoControllerFound,
}

impl AhciError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bar5NotConfigured => "AHCI BAR5 not configured",
            Self::HbaResetTimeout => "HBA reset timeout",
            Self::BiosHandoffTimeout => "BIOS handoff timeout",
            Self::PortCmdListStopTimeout => "Port command list runner didn't stop",
            Self::PortFisStopTimeout => "Port FIS runner didn't stop",
            Self::ZeroSectorCapacity => "Device reports zero sectors",
            Self::PortNotInitialized => "Port not initialized",
            Self::LbaRangeExceeded => "LBA range exceeds device capacity",
            Self::LbaOverflow => "LBA range overflow",
            Self::InvalidBufferSize => "Invalid buffer size: 0",
            Self::BufferAddressOverflow => "Buffer address overflow",
            Self::BufferInCriticalRegion => "DMA buffer overlaps kernel critical region",
            Self::BufferNotAligned => "DMA buffer not properly aligned",
            Self::NoFreeSlots => "No free command slots",
            Self::CommandFailed => "AHCI command failed (TFES/ERR)",
            Self::CommandTimeout => "AHCI command timeout",
            Self::TrimNotSupported => "Device does not support TRIM",
            Self::TrimRateLimitExceeded => "TRIM rate limit exceeded",
            Self::SecureEraseNotSupported => "Device does not support secure erase",
            Self::CipherNotInitialized => "AES cipher not initialized",
            Self::PortDmaNotInitialized => "Port DMA not initialized",
            Self::DmaAllocationFailed => "DMA allocation failed",
            Self::PortResetFailed => "Port reset failed",
            Self::NoControllerFound => "No AHCI controller found",
        }
    }
}

impl fmt::Display for AhciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&'static str> for AhciError {
    fn from(s: &'static str) -> Self {
        match s {
            "AHCI BAR5 not configured" => Self::Bar5NotConfigured,
            "Port not initialized" => Self::PortNotInitialized,
            "Device does not support TRIM" => Self::TrimNotSupported,
            "TRIM rate limit exceeded" => Self::TrimRateLimitExceeded,
            "Device does not support secure erase" => Self::SecureEraseNotSupported,
            "Device reports zero sectors" => Self::ZeroSectorCapacity,
            "Port command list runner didn't stop" => Self::PortCmdListStopTimeout,
            "Port FIS runner didn't stop" => Self::PortFisStopTimeout,
            _ => Self::CommandFailed,
        }
    }
}
