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
pub enum XhciError {
    InvalidSlotId(u8),
    InvalidPortNumber(u8),
    SlotNotEnabled(u8),
    PortNotConnected(u8),
    InvalidTrbType(u32),
    TrbMisaligned(u64),
    TrbRingFull,
    TrbValidationFailed,
    InvalidDmaAddress(u64),
    DmaBufferMisaligned(u64),
    BufferSizeMismatch { expected: usize, actual: usize },
    TransferTooLarge(usize),
    DmaAllocationFailed(usize),
    Timeout,
    TimeoutWithReset,
    ControllerResetTimeout,
    PortResetTimeout,
    CommandTimeout,
    TransferTimeout,
    InvalidDescriptorLength(usize),
    DescriptorTooSmall(usize),
    DescriptorTooLarge(usize),
    DescriptorTypeMismatch { expected: u8, actual: u8 },
    RateLimitExceeded,
    EnumerationLimitExceeded,
    EnumerationFailed,
    CompletionCodeError(u8),
    TransferLengthOverflow,
    InvalidCompletion,
    ShortPacket { expected: usize, actual: usize },
    BabbleDetected,
    TransactionError,
    Stall,
    NotInitialized,
    AlreadyInitialized,
    AllocationFailed,
    BarNotPresent,
    BarNotMmio,
    ControllerNotReady,
    HostControllerHalted,
    HostSystemError,
    CapabilityNotSupported,
    ExtendedCapabilityError,
    DeviceContextNotAllocated(u8),
    InputContextInvalid,
    EndpointNotConfigured(u8),
    EndpointAlreadyEnabled(u8),
    Ep0RingNotReady,
    ProtocolError,
    DeviceNotResponding,
    InvalidDeviceSpeed(u32),
    InternalError(&'static str),
}

impl XhciError {
    pub fn as_str(&self) -> &'static str {
        match self {
            XhciError::InvalidSlotId(_) => "Invalid slot ID",
            XhciError::InvalidPortNumber(_) => "Invalid port number",
            XhciError::SlotNotEnabled(_) => "Slot not enabled",
            XhciError::PortNotConnected(_) => "Port not connected",
            XhciError::InvalidTrbType(_) => "Invalid TRB type",
            XhciError::TrbMisaligned(_) => "TRB pointer misaligned",
            XhciError::TrbRingFull => "TRB ring full",
            XhciError::TrbValidationFailed => "TRB validation failed",
            XhciError::InvalidDmaAddress(_) => "Invalid DMA address",
            XhciError::DmaBufferMisaligned(_) => "DMA buffer misaligned",
            XhciError::BufferSizeMismatch { .. } => "Buffer size mismatch",
            XhciError::TransferTooLarge(_) => "Transfer size too large",
            XhciError::DmaAllocationFailed(_) => "DMA allocation failed",
            XhciError::Timeout => "Operation timeout",
            XhciError::TimeoutWithReset => "Timeout (endpoint reset required)",
            XhciError::ControllerResetTimeout => "Controller reset timeout",
            XhciError::PortResetTimeout => "Port reset timeout",
            XhciError::CommandTimeout => "Command completion timeout",
            XhciError::TransferTimeout => "Transfer completion timeout",
            XhciError::InvalidDescriptorLength(_) => "Invalid descriptor length",
            XhciError::DescriptorTooSmall(_) => "Descriptor too small",
            XhciError::DescriptorTooLarge(_) => "Descriptor too large",
            XhciError::DescriptorTypeMismatch { .. } => "Descriptor type mismatch",
            XhciError::RateLimitExceeded => "Enumeration rate limit exceeded",
            XhciError::EnumerationLimitExceeded => "Too many enumeration attempts",
            XhciError::EnumerationFailed => "Device enumeration failed",
            XhciError::CompletionCodeError(_) => "Command/transfer completion error",
            XhciError::TransferLengthOverflow => "Transfer length overflow",
            XhciError::InvalidCompletion => "Invalid completion event",
            XhciError::ShortPacket { .. } => "Short packet received",
            XhciError::BabbleDetected => "Babble detected",
            XhciError::TransactionError => "Transaction error",
            XhciError::Stall => "Endpoint stalled",
            XhciError::NotInitialized => "Controller not initialized",
            XhciError::AlreadyInitialized => "Controller already initialized",
            XhciError::AllocationFailed => "Memory allocation failed",
            XhciError::BarNotPresent => "BAR0 not present",
            XhciError::BarNotMmio => "BAR0 is not MMIO",
            XhciError::ControllerNotReady => "Controller not ready",
            XhciError::HostControllerHalted => "Host controller halted",
            XhciError::HostSystemError => "Host system error",
            XhciError::CapabilityNotSupported => "Required capability not supported",
            XhciError::ExtendedCapabilityError => "Extended capability parse error",
            XhciError::DeviceContextNotAllocated(_) => "Device context not allocated",
            XhciError::InputContextInvalid => "Input context invalid",
            XhciError::EndpointNotConfigured(_) => "Endpoint not configured",
            XhciError::EndpointAlreadyEnabled(_) => "Endpoint already enabled",
            XhciError::Ep0RingNotReady => "EP0 ring not ready",
            XhciError::ProtocolError => "USB protocol error",
            XhciError::DeviceNotResponding => "Device not responding",
            XhciError::InvalidDeviceSpeed(_) => "Invalid device speed",
            XhciError::InternalError(msg) => msg,
        }
    }

    pub fn completion_code(&self) -> Option<u8> {
        match self {
            XhciError::CompletionCodeError(code) => Some(*code),
            _ => None,
        }
    }

    pub fn requires_endpoint_reset(&self) -> bool {
        matches!(
            self,
            XhciError::TimeoutWithReset
                | XhciError::Stall
                | XhciError::BabbleDetected
                | XhciError::TransactionError
        )
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            XhciError::Timeout
                | XhciError::TransferTimeout
                | XhciError::ShortPacket { .. }
                | XhciError::Stall
                | XhciError::RateLimitExceeded
        )
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            XhciError::HostSystemError
                | XhciError::ControllerNotReady
                | XhciError::InternalError(_)
        )
    }

    pub fn from_completion_code(code: u8) -> Option<Self> {
        match code {
            1 => None,
            2 => Some(XhciError::TransferLengthOverflow),
            3 => Some(XhciError::BabbleDetected),
            4 => Some(XhciError::TransactionError),
            5 => Some(XhciError::TrbValidationFailed),
            6 => Some(XhciError::Stall),
            13 => Some(XhciError::ShortPacket {
                expected: 0,
                actual: 0,
            }),
            _ => Some(XhciError::CompletionCodeError(code)),
        }
    }
}

impl fmt::Display for XhciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XhciError::InvalidSlotId(id) => write!(f, "Invalid slot ID: {}", id),
            XhciError::InvalidPortNumber(port) => write!(f, "Invalid port number: {}", port),
            XhciError::SlotNotEnabled(id) => write!(f, "Slot {} not enabled", id),
            XhciError::PortNotConnected(port) => write!(f, "Port {} not connected", port),
            XhciError::InvalidTrbType(t) => write!(f, "Invalid TRB type: {}", t),
            XhciError::TrbMisaligned(addr) => write!(f, "TRB pointer misaligned: {:#x}", addr),
            XhciError::InvalidDmaAddress(addr) => write!(f, "Invalid DMA address: {:#x}", addr),
            XhciError::DmaBufferMisaligned(addr) => {
                write!(f, "DMA buffer misaligned: {:#x}", addr)
            }
            XhciError::BufferSizeMismatch { expected, actual } => {
                write!(f, "Buffer size mismatch: expected {}, got {}", expected, actual)
            }
            XhciError::TransferTooLarge(size) => write!(f, "Transfer too large: {} bytes", size),
            XhciError::DmaAllocationFailed(size) => {
                write!(f, "DMA allocation failed for {} bytes", size)
            }
            XhciError::InvalidDescriptorLength(len) => {
                write!(f, "Invalid descriptor length: {}", len)
            }
            XhciError::DescriptorTooSmall(len) => write!(f, "Descriptor too small: {} bytes", len),
            XhciError::DescriptorTooLarge(len) => write!(f, "Descriptor too large: {} bytes", len),
            XhciError::DescriptorTypeMismatch { expected, actual } => {
                write!(f, "Descriptor type mismatch: expected {}, got {}", expected, actual)
            }
            XhciError::CompletionCodeError(code) => write!(f, "Completion error code: {}", code),
            XhciError::ShortPacket { expected, actual } => {
                write!(f, "Short packet: expected {} bytes, got {}", expected, actual)
            }
            XhciError::DeviceContextNotAllocated(slot) => {
                write!(f, "Device context not allocated for slot {}", slot)
            }
            XhciError::EndpointNotConfigured(ep) => write!(f, "Endpoint {} not configured", ep),
            XhciError::EndpointAlreadyEnabled(ep) => write!(f, "Endpoint {} already enabled", ep),
            XhciError::InvalidDeviceSpeed(speed) => write!(f, "Invalid device speed: {}", speed),
            XhciError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

pub type XhciResult<T> = Result<T, XhciError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = XhciError::InvalidSlotId(5);
        assert_eq!(format!("{}", err), "Invalid slot ID: 5");
    }

    #[test]
    fn test_error_as_str() {
        let err = XhciError::Timeout;
        assert_eq!(err.as_str(), "Operation timeout");
    }

    #[test]
    fn test_completion_code() {
        let err = XhciError::CompletionCodeError(6);
        assert_eq!(err.completion_code(), Some(6));

        let err = XhciError::Timeout;
        assert_eq!(err.completion_code(), None);
    }

    #[test]
    fn test_requires_reset() {
        assert!(XhciError::Stall.requires_endpoint_reset());
        assert!(!XhciError::Timeout.requires_endpoint_reset());
    }

    #[test]
    fn test_from_completion_code() {
        assert!(XhciError::from_completion_code(1).is_none());
        assert!(matches!(
            XhciError::from_completion_code(6),
            Some(XhciError::Stall)
        ));
    }
}
