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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    NotInitialized,
    AlreadyInitialized,
    DeviceNotFound { bus: u8, slot: u8, function: u8 },
    InvalidBarIndex { index: u8 },
    BarNotImplemented { bar: u8 },
    Bar64BitSpansTwo { bar: u8 },
    CapabilityNotFound { cap_id: u8 },
    MsixNotSupported,
    MsiNotSupported,
    DmaAllocationFailed { size: usize },
    DmaNotAligned { addr: u64, required: usize },
    InvalidConfigAccess { bus: u8, slot: u8, function: u8, offset: u16 },
    BusMasteringDisabled,
    MemorySpaceDisabled,
    IoSpaceDisabled,
    ConfigAccessDenied,
    DeviceError { status: u16 },
    Timeout,
}

impl PciError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "PCI subsystem not initialized",
            Self::AlreadyInitialized => "PCI subsystem already initialized",
            Self::DeviceNotFound { .. } => "PCI device not found at specified location",
            Self::InvalidBarIndex { .. } => "invalid BAR index (must be 0-5)",
            Self::BarNotImplemented { .. } => "BAR not implemented by device",
            Self::Bar64BitSpansTwo { .. } => "64-bit BAR spans two consecutive BARs",
            Self::CapabilityNotFound { .. } => "PCI capability not found",
            Self::MsixNotSupported => "MSI-X not supported by device",
            Self::MsiNotSupported => "MSI not supported by device",
            Self::DmaAllocationFailed { .. } => "DMA buffer allocation failed",
            Self::DmaNotAligned { .. } => "DMA buffer not properly aligned",
            Self::InvalidConfigAccess { .. } => "invalid PCI configuration access",
            Self::BusMasteringDisabled => "bus mastering not enabled on device",
            Self::MemorySpaceDisabled => "memory space access not enabled",
            Self::IoSpaceDisabled => "I/O space access not enabled",
            Self::ConfigAccessDenied => "PCI configuration access denied",
            Self::DeviceError { .. } => "PCI device reported error",
            Self::Timeout => "timeout waiting for PCI device",
        }
    }
}

pub type PciResult<T> = Result<T, PciError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(PciError::NotInitialized.as_str(), "PCI subsystem not initialized");
        assert_eq!(PciError::MsixNotSupported.as_str(), "MSI-X not supported by device");
    }
}
