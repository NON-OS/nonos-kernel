// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! AHCI driver error types.

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciError {
    /// PCI BAR5 (AHCI MMIO base) is not configured
    Bar5NotConfigured,
    /// HBA reset operation timed out
    HbaResetTimeout,
    /// BIOS-to-OS handoff timed out
    BiosHandoffTimeout,
    /// Port command list runner failed to stop
    PortCmdListStopTimeout,
    /// Port FIS receiver failed to stop
    PortFisStopTimeout,
    /// Device reports zero sector capacity
    ZeroSectorCapacity,
    /// Specified port is not initialized
    PortNotInitialized,
    /// LBA range exceeds device capacity
    LbaRangeExceeded,
    /// LBA calculation overflow
    LbaOverflow,
    /// DMA buffer size is invalid (zero)
    InvalidBufferSize,
    /// DMA buffer address overflow
    BufferAddressOverflow,
    /// DMA buffer overlaps kernel critical region
    BufferInCriticalRegion,
    /// DMA buffer not properly aligned
    BufferNotAligned,
    /// No free command slots available
    NoFreeSlots,
    /// ATA command execution failed (Task File Error Status)
    CommandFailed,
    /// Command execution timed out
    CommandTimeout,
    /// Device does not support TRIM
    TrimNotSupported,
    /// TRIM rate limit exceeded
    TrimRateLimitExceeded,
    /// Device does not support secure erase
    SecureEraseNotSupported,
    /// AES cipher not initialized
    CipherNotInitialized,
    /// Port DMA structures not initialized
    PortDmaNotInitialized,
    /// DMA allocation failed
    DmaAllocationFailed,
    /// Port reset failed
    PortResetFailed,
    /// No AHCI controller found on PCI bus
    NoControllerFound,
}
/// Returns a human-readable description of the error.
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
// Allow conversion from &'static str for backward compatibility
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
            _ => Self::CommandFailed, // Default fallback
        }
    }
}
