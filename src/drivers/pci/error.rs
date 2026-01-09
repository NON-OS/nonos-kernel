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

//! PCI error types.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    InvalidBus(u8),
    InvalidDevice(u8),
    InvalidFunction(u8),
    InvalidOffset(u16),
    UnalignedAccess { offset: u16, alignment: u8 },
    ProtectedRegister { offset: u16 },
    ReadOnlyRegister { offset: u16 },
    SecurityViolation(SecurityViolation),
    InvalidBarIndex(u8),
    InvalidBarAddress(u64),
    BarTooLarge { size: u64, max: u64 },
    BarOverlapsProtected { address: u64, region: ProtectedRegion },
    BarNotPresent(u8),
    BarTypeMismatch { index: u8, expected: BarType, found: BarType },
    DeviceBlocked { vendor: u16, device: u16 },
    DeviceNotAllowed { vendor: u16, device: u16 },
    DeviceNotFound,
    NoDevicesFound,
    CapabilityNotFound(u8),
    InvalidCapabilityPointer(u8),
    MsiNotSupported,
    MsixNotSupported,
    MsixTableAccessFailed,
    MsixVectorOutOfRange { vector: u16, max: u16 },
    ConfigAccessFailed { bus: u8, device: u8, function: u8, offset: u16 },
    BusMasterNotEnabled,
    MemorySpaceNotEnabled,
    IoSpaceNotEnabled,
    InterruptDisabled,
    PcieNotSupported,
    PcieSpeedNotSupported(u8),
    PcieLinkTrainingFailed,
    PcieLinkDown,
    AcsNotSupported,
    AcsViolation(AcsViolation),
    IommuNotAvailable,
    DmaProtectionFailed,
    PowerManagementFailed(PmError),
    HotplugFailed(HotplugError),
    ResourceAllocationFailed,
    BridgeConfigFailed,
    RootComplexError,
    ManagerNotInitialized,
    AlreadyInitialized,
    InternalError(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityViolation {
    UnauthorizedConfigWrite,
    RomBaseModification,
    BusMasterWithoutApproval,
    BarProgrammingBlocked,
    ExpansionRomBlocked,
    InterruptLineModification,
    BridgeWindowModification,
    VendorIdTampering,
    ClassCodeTampering,
    MaxViolations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedRegion {
    LegacyBios,
    KernelCode,
    KernelData,
    PageTables,
    IoapicMmio,
    LocalApicMmio,
    ReservedMemory,
    AcpiRegion,
    PciConfigSpace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    Memory32,
    Memory64,
    Io,
    NotPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcsViolation {
    SourceValidation,
    TranslationBlocking,
    P2PRequestRedirect,
    P2PCompletionRedirect,
    UpstreamForwarding,
    P2PEgressControl,
    DirectTranslatedP2P,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmError {
    D0TransitionFailed,
    D1TransitionFailed,
    D2TransitionFailed,
    D3HotTransitionFailed,
    D3ColdTransitionFailed,
    PmeNotSupported,
    PmeEnableFailed,
    InvalidPowerState(u8),
    TransitionTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugError {
    SlotNotPresent,
    SlotOccupied,
    SlotEmpty,
    PowerFault,
    AttentionButtonPressed,
    CardNotSeated,
    InterLockOpen,
    CommandTimeout,
    SurpriseRemoval,
}

impl fmt::Display for PciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PciError::InvalidBus(bus) => write!(f, "Invalid PCI bus number: {}", bus),
            PciError::InvalidDevice(dev) => write!(f, "Invalid PCI device number: {} (max 31)", dev),
            PciError::InvalidFunction(func) => write!(f, "Invalid PCI function number: {} (max 7)", func),
            PciError::InvalidOffset(off) => write!(f, "Invalid config space offset: 0x{:04x}", off),
            PciError::UnalignedAccess { offset, alignment } => {
                write!(f, "Unaligned config access: offset 0x{:04x} not {}-byte aligned", offset, alignment)
            }
            PciError::ProtectedRegister { offset } => {
                write!(f, "Access to protected register at offset 0x{:04x} blocked", offset)
            }
            PciError::ReadOnlyRegister { offset } => {
                write!(f, "Write to read-only register at offset 0x{:04x} blocked", offset)
            }
            PciError::SecurityViolation(v) => write!(f, "Security violation: {:?}", v),
            PciError::InvalidBarIndex(idx) => write!(f, "Invalid BAR index: {} (max 5)", idx),
            PciError::InvalidBarAddress(addr) => write!(f, "Invalid BAR address: 0x{:016x}", addr),
            PciError::BarTooLarge { size, max } => {
                write!(f, "BAR size {} exceeds maximum {} bytes", size, max)
            }
            PciError::BarOverlapsProtected { address, region } => {
                write!(f, "BAR at 0x{:016x} overlaps protected region: {:?}", address, region)
            }
            PciError::BarNotPresent(idx) => write!(f, "BAR {} not present", idx),
            PciError::BarTypeMismatch { index, expected, found } => {
                write!(f, "BAR {} type mismatch: expected {:?}, found {:?}", index, expected, found)
            }
            PciError::DeviceBlocked { vendor, device } => {
                write!(f, "Device {:04x}:{:04x} is blocked by security policy", vendor, device)
            }
            PciError::DeviceNotAllowed { vendor, device } => {
                write!(f, "Device {:04x}:{:04x} not in allowlist", vendor, device)
            }
            PciError::DeviceNotFound => write!(f, "PCI device not found"),
            PciError::NoDevicesFound => write!(f, "No PCI devices found during enumeration"),
            PciError::CapabilityNotFound(id) => write!(f, "PCI capability 0x{:02x} not found", id),
            PciError::InvalidCapabilityPointer(ptr) => {
                write!(f, "Invalid capability pointer: 0x{:02x}", ptr)
            }
            PciError::MsiNotSupported => write!(f, "MSI not supported by device"),
            PciError::MsixNotSupported => write!(f, "MSI-X not supported by device"),
            PciError::MsixTableAccessFailed => write!(f, "Failed to access MSI-X table"),
            PciError::MsixVectorOutOfRange { vector, max } => {
                write!(f, "MSI-X vector {} out of range (max {})", vector, max)
            }
            PciError::ConfigAccessFailed { bus, device, function, offset } => {
                write!(f, "Config access failed: {:02x}:{:02x}.{} offset 0x{:04x}",
                       bus, device, function, offset)
            }
            PciError::BusMasterNotEnabled => write!(f, "Bus master not enabled"),
            PciError::MemorySpaceNotEnabled => write!(f, "Memory space not enabled"),
            PciError::IoSpaceNotEnabled => write!(f, "I/O space not enabled"),
            PciError::InterruptDisabled => write!(f, "Interrupt disabled"),
            PciError::PcieNotSupported => write!(f, "PCIe capability not found"),
            PciError::PcieSpeedNotSupported(speed) => write!(f, "PCIe speed Gen{} not supported", speed),
            PciError::PcieLinkTrainingFailed => write!(f, "PCIe link training failed"),
            PciError::PcieLinkDown => write!(f, "PCIe link is down"),
            PciError::AcsNotSupported => write!(f, "ACS not supported"),
            PciError::AcsViolation(v) => write!(f, "ACS violation: {:?}", v),
            PciError::IommuNotAvailable => write!(f, "IOMMU not available"),
            PciError::DmaProtectionFailed => write!(f, "DMA protection setup failed"),
            PciError::PowerManagementFailed(e) => write!(f, "Power management failed: {:?}", e),
            PciError::HotplugFailed(e) => write!(f, "Hotplug failed: {:?}", e),
            PciError::ResourceAllocationFailed => write!(f, "Resource allocation failed"),
            PciError::BridgeConfigFailed => write!(f, "Bridge configuration failed"),
            PciError::RootComplexError => write!(f, "Root complex error"),
            PciError::ManagerNotInitialized => write!(f, "PCI manager not initialized"),
            PciError::AlreadyInitialized => write!(f, "PCI subsystem already initialized"),
            PciError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl PciError {
    pub fn is_fatal(&self) -> bool {
        matches!(self,
            PciError::RootComplexError |
            PciError::BridgeConfigFailed |
            PciError::PcieLinkDown |
            PciError::InternalError(_)
        )
    }

    pub fn is_security_related(&self) -> bool {
        matches!(self,
            PciError::SecurityViolation(_) |
            PciError::DeviceBlocked { .. } |
            PciError::DeviceNotAllowed { .. } |
            PciError::ProtectedRegister { .. } |
            PciError::BarOverlapsProtected { .. } |
            PciError::AcsViolation(_) |
            PciError::DmaProtectionFailed
        )
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(self,
            PciError::DeviceNotFound |
            PciError::CapabilityNotFound(_) |
            PciError::MsiNotSupported |
            PciError::MsixNotSupported |
            PciError::BarNotPresent(_)
        )
    }
}

impl From<SecurityViolation> for PciError {
    fn from(v: SecurityViolation) -> Self {
        PciError::SecurityViolation(v)
    }
}

impl From<PmError> for PciError {
    fn from(e: PmError) -> Self {
        PciError::PowerManagementFailed(e)
    }
}

impl From<HotplugError> for PciError {
    fn from(e: HotplugError) -> Self {
        PciError::HotplugFailed(e)
    }
}

pub type Result<T> = core::result::Result<T, PciError>;
