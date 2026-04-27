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

use super::nvme_error::NvmeError;
use core::fmt;

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
            Self::InterruptAllocationFailed => "Interrupt allocation failed",
            Self::InterruptTimeout => "Interrupt wait timeout",
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
            Self::ControllerFatalStatus | Self::CqCorruption | Self::DmaBufferOverlapsKernel
        )
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::CommandTimeout | Self::RateLimitExceeded | Self::QueueFull)
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
