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

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeError {
    NoControllerFound,
    Bar0NotMmio,
    ControllerDisableTimeout,
    ControllerEnableTimeout,
    ControllerFatalStatus,
    AdminQueueCreationFailed,
    IoQueueCreationFailed,
    IdentifyControllerFailed,
    IdentifyNamespaceFailed,
    NoActiveNamespaces,
    NamespaceNotReady,
    InvalidNamespaceId,
    LbaRangeOverflow,
    LbaExceedsCapacity,
    InvalidBlockCount,
    DmaAllocationFailed,
    DmaBufferTooLarge,
    DmaBufferSizeZero,
    DmaBufferOverlapsKernel,
    DmaBufferAddressOverflow,
    PrpListAllocationFailed,
    CommandTimeout,
    CommandFailed { status_code: u16 },
    CqCorruption,
    CidMismatch,
    PhaseTagError,
    RateLimitExceeded,
    IoQueueNotReady,
    QueueFull,
    InvalidPrpAlignment,
    MsixConfigurationFailed,
    ControllerNotInitialized,
    SubmissionQueueError,
    CompletionQueueError,
    InvalidQueueSize,
    UnsupportedPageSize,
    CapabilityReadError,
    DoorbellStrideError,
}

impl NvmeError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoControllerFound => "No NVMe controller found on PCI bus",
            Self::Bar0NotMmio => "NVMe BAR0 is not memory-mapped I/O",
            Self::ControllerDisableTimeout => "Timeout waiting for controller disable",
            Self::ControllerEnableTimeout => "Timeout waiting for controller ready",
            Self::ControllerFatalStatus => "Controller reported fatal status",
            Self::AdminQueueCreationFailed => "Failed to create admin queue",
            Self::IoQueueCreationFailed => "Failed to create I/O queue",
            Self::IdentifyControllerFailed => "Identify Controller command failed",
            Self::IdentifyNamespaceFailed => "Identify Namespace command failed",
            Self::NoActiveNamespaces => "No active namespaces found",
            Self::NamespaceNotReady => "Namespace not initialized",
            Self::InvalidNamespaceId => "Invalid namespace ID",
            Self::LbaRangeOverflow => "LBA range calculation overflow",
            Self::LbaExceedsCapacity => "LBA range exceeds namespace capacity",
            Self::InvalidBlockCount => "Invalid block count (zero)",
            Self::DmaAllocationFailed => "DMA memory allocation failed",
            Self::DmaBufferTooLarge => "DMA buffer exceeds maximum size",
            Self::DmaBufferSizeZero => "DMA buffer size is zero",
            Self::DmaBufferOverlapsKernel => "DMA buffer overlaps kernel memory",
            Self::DmaBufferAddressOverflow => "DMA buffer address overflow",
            Self::PrpListAllocationFailed => "PRP list allocation failed",
            Self::CommandTimeout => "Command completion timeout",
            Self::CommandFailed { .. } => "Command failed with status code",
            Self::CqCorruption => "Completion queue corruption detected",
            Self::CidMismatch => "Command ID mismatch in completion",
            Self::PhaseTagError => "Phase tag error in completion queue",
            Self::RateLimitExceeded => "Command rate limit exceeded",
            Self::IoQueueNotReady => "I/O queue not initialized",
            Self::QueueFull => "Queue is full",
            Self::InvalidPrpAlignment => "PRP address not properly aligned",
            Self::MsixConfigurationFailed => "MSI-X configuration failed",
            Self::ControllerNotInitialized => "NVMe controller not initialized",
            Self::SubmissionQueueError => "Submission queue error",
            Self::CompletionQueueError => "Completion queue error",
            Self::InvalidQueueSize => "Invalid queue size",
            Self::UnsupportedPageSize => "Unsupported memory page size",
            Self::CapabilityReadError => "Failed to read controller capabilities",
            Self::DoorbellStrideError => "Invalid doorbell stride",
        }
    }

    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::ControllerFatalStatus
                | Self::CqCorruption
                | Self::DmaBufferOverlapsKernel
        )
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::CommandTimeout
                | Self::RateLimitExceeded
                | Self::QueueFull
        )
    }
}

impl fmt::Display for NvmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandFailed { status_code } => {
                write!(f, "NVMe command failed (SC=0x{:03X})", status_code)
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

impl From<&'static str> for NvmeError {
    fn from(s: &'static str) -> Self {
        match s {
            "No NVMe controller found" => Self::NoControllerFound,
            "NVMe BAR0 is not MMIO" => Self::Bar0NotMmio,
            "NVMe: timeout waiting for CC.EN=0 -> CSTS.RDY=0" => Self::ControllerDisableTimeout,
            "NVMe: timeout waiting for CSTS.RDY=1" => Self::ControllerEnableTimeout,
            "NVMe: namespace not ready" => Self::NamespaceNotReady,
            "NVMe: LBA range overflow" => Self::LbaRangeOverflow,
            "NVMe: LBA range exceeds namespace capacity" => Self::LbaExceedsCapacity,
            "NVMe: invalid block count (zero)" => Self::InvalidBlockCount,
            "NVMe: DMA buffer too large" => Self::DmaBufferTooLarge,
            "NVMe: DMA buffer size is zero" => Self::DmaBufferSizeZero,
            "NVMe: DMA buffer overlaps kernel memory" => Self::DmaBufferOverlapsKernel,
            "NVMe: Rate limit exceeded" => Self::RateLimitExceeded,
            "NVMe: IO queue not ready" => Self::IoQueueNotReady,
            "NVMe: CQ poll timeout" => Self::CommandTimeout,
            "NVMe: CQ corruption detected (too many CID mismatches)" => Self::CqCorruption,
            "NVMe: Command failed (SC != 0)" => Self::CommandFailed { status_code: 0 },
            "NVMe not initialized" => Self::ControllerNotInitialized,
            _ => Self::CommandFailed { status_code: 0xFFFF },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeStatusCode {
    Success,
    InvalidOpcode,
    InvalidField,
    CommandIdConflict,
    DataTransferError,
    CommandAbortedPower,
    InternalError,
    CommandAbortedSq,
    FusedCommandMissing,
    FusedCommandMismatch,
    InvalidNamespaceFormat,
    CommandSequenceError,
    InvalidSglSegmentDescriptor,
    InvalidSglCount,
    DataSglLengthInvalid,
    MetadataSglLengthInvalid,
    SglTypeInvalid,
    InvalidControllerMemory,
    InvalidPrpOffset,
    AtomicWriteUnitExceeded,
    OperationDenied,
    SglDataBlockInvalid,
    NamespaceIdentifierUnavailable,
    ZoneInvalidTransition,
    ZoneBoundaryError,
    ZoneFull,
    ZoneReadOnly,
    ZoneOffline,
    ZoneInvalidWrite,
    TooManyActiveZones,
    TooManyOpenZones,
    InvalidZoneState,
    LbaOutOfRange,
    CapacityExceeded,
    NamespaceNotReady,
    ReservationConflict,
    FormatInProgress,
    ZoneResetPending,
    GenericError,
    MediaError,
    Unknown(u16),
}

impl NvmeStatusCode {
    pub fn from_status_field(status: u16) -> Self {
        let sc = (status >> 1) & 0xFF;
        let sct = (status >> 9) & 0x7;

        match (sct, sc) {
            (0, 0x00) => Self::Success,
            (0, 0x01) => Self::InvalidOpcode,
            (0, 0x02) => Self::InvalidField,
            (0, 0x03) => Self::CommandIdConflict,
            (0, 0x04) => Self::DataTransferError,
            (0, 0x05) => Self::CommandAbortedPower,
            (0, 0x06) => Self::InternalError,
            (0, 0x07) => Self::CommandAbortedSq,
            (0, 0x08) => Self::FusedCommandMissing,
            (0, 0x09) => Self::FusedCommandMismatch,
            (0, 0x0A) => Self::InvalidNamespaceFormat,
            (0, 0x0B) => Self::CommandSequenceError,
            (0, 0x0C) => Self::InvalidSglSegmentDescriptor,
            (0, 0x0D) => Self::InvalidSglCount,
            (0, 0x0E) => Self::DataSglLengthInvalid,
            (0, 0x0F) => Self::MetadataSglLengthInvalid,
            (0, 0x10) => Self::SglTypeInvalid,
            (0, 0x11) => Self::InvalidControllerMemory,
            (0, 0x12) => Self::InvalidPrpOffset,
            (0, 0x13) => Self::AtomicWriteUnitExceeded,
            (0, 0x14) => Self::OperationDenied,
            (0, 0x15) => Self::SglDataBlockInvalid,
            (0, 0x18) => Self::NamespaceIdentifierUnavailable,
            (0, 0xB8) => Self::ZoneInvalidTransition,
            (0, 0xB9) => Self::ZoneBoundaryError,
            (0, 0xBA) => Self::ZoneFull,
            (0, 0xBB) => Self::ZoneReadOnly,
            (0, 0xBC) => Self::ZoneOffline,
            (0, 0xBD) => Self::ZoneInvalidWrite,
            (0, 0xBE) => Self::TooManyActiveZones,
            (0, 0xBF) => Self::TooManyOpenZones,
            (0, 0xC0) => Self::InvalidZoneState,
            (2, 0x80) => Self::LbaOutOfRange,
            (2, 0x81) => Self::CapacityExceeded,
            (2, 0x82) => Self::NamespaceNotReady,
            (2, 0x83) => Self::ReservationConflict,
            (2, 0x84) => Self::FormatInProgress,
            (2, 0xBD) => Self::ZoneResetPending,
            (3, _) => Self::MediaError,
            _ => Self::Unknown(status),
        }
    }

    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub const fn is_media_error(&self) -> bool {
        matches!(self, Self::MediaError | Self::DataTransferError)
    }

    pub const fn is_namespace_error(&self) -> bool {
        matches!(
            self,
            Self::NamespaceNotReady
                | Self::InvalidNamespaceFormat
                | Self::NamespaceIdentifierUnavailable
        )
    }
}

impl fmt::Display for NvmeStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::InvalidOpcode => write!(f, "Invalid Command Opcode"),
            Self::InvalidField => write!(f, "Invalid Field in Command"),
            Self::CommandIdConflict => write!(f, "Command ID Conflict"),
            Self::DataTransferError => write!(f, "Data Transfer Error"),
            Self::CommandAbortedPower => write!(f, "Command Aborted Due to Power Loss"),
            Self::InternalError => write!(f, "Internal Error"),
            Self::CommandAbortedSq => write!(f, "Command Aborted by SQ Deletion"),
            Self::FusedCommandMissing => write!(f, "Fused Command Missing"),
            Self::FusedCommandMismatch => write!(f, "Fused Command Mismatch"),
            Self::InvalidNamespaceFormat => write!(f, "Invalid Namespace or Format"),
            Self::CommandSequenceError => write!(f, "Command Sequence Error"),
            Self::InvalidSglSegmentDescriptor => write!(f, "Invalid SGL Segment Descriptor"),
            Self::InvalidSglCount => write!(f, "Invalid Number of SGL Descriptors"),
            Self::DataSglLengthInvalid => write!(f, "Data SGL Length Invalid"),
            Self::MetadataSglLengthInvalid => write!(f, "Metadata SGL Length Invalid"),
            Self::SglTypeInvalid => write!(f, "SGL Descriptor Type Invalid"),
            Self::InvalidControllerMemory => write!(f, "Invalid Use of Controller Memory Buffer"),
            Self::InvalidPrpOffset => write!(f, "Invalid PRP Offset"),
            Self::AtomicWriteUnitExceeded => write!(f, "Atomic Write Unit Exceeded"),
            Self::OperationDenied => write!(f, "Operation Denied"),
            Self::SglDataBlockInvalid => write!(f, "SGL Data Block Granularity Invalid"),
            Self::NamespaceIdentifierUnavailable => write!(f, "Namespace Identifier Unavailable"),
            Self::ZoneInvalidTransition => write!(f, "Zone Invalid State Transition"),
            Self::ZoneBoundaryError => write!(f, "Zone Boundary Error"),
            Self::ZoneFull => write!(f, "Zone Full"),
            Self::ZoneReadOnly => write!(f, "Zone Read Only"),
            Self::ZoneOffline => write!(f, "Zone Offline"),
            Self::ZoneInvalidWrite => write!(f, "Zone Invalid Write"),
            Self::TooManyActiveZones => write!(f, "Too Many Active Zones"),
            Self::TooManyOpenZones => write!(f, "Too Many Open Zones"),
            Self::InvalidZoneState => write!(f, "Invalid Zone State Transition"),
            Self::LbaOutOfRange => write!(f, "LBA Out of Range"),
            Self::CapacityExceeded => write!(f, "Capacity Exceeded"),
            Self::NamespaceNotReady => write!(f, "Namespace Not Ready"),
            Self::ReservationConflict => write!(f, "Reservation Conflict"),
            Self::FormatInProgress => write!(f, "Format in Progress"),
            Self::ZoneResetPending => write!(f, "Zone Reset Recommended"),
            Self::GenericError => write!(f, "Generic Error"),
            Self::MediaError => write!(f, "Media/Data Integrity Error"),
            Self::Unknown(code) => write!(f, "Unknown Status Code 0x{:04X}", code),
        }
    }
}
