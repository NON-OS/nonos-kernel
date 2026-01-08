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
pub enum VirtioNetError {
    InvalidPacketSize,
    PacketTooSmall,
    PacketExceedsMtu,
    InvalidHeader,
    DescriptorOutOfBounds,
    DescriptorChainTooLong,
    InvalidDmaAddress,
    RateLimitExceeded,
    NoBuffersAvailable,
    NoDescriptorsAvailable,
    QueueError,
    InvalidMacAddress,
    MalformedPacket,
    ChecksumError,
    DeviceNotReady,
    BufferTooSmall,
    InitializationFailed,
    FeatureNegotiationFailed,
    MsixConfigurationFailed,
    QueueSetupFailed,
    AllocationFailed,
    GenericError,
}

impl VirtioNetError {
    pub fn as_str(&self) -> &'static str {
        match self {
            VirtioNetError::InvalidPacketSize => "invalid packet size",
            VirtioNetError::PacketTooSmall => "packet too small",
            VirtioNetError::PacketExceedsMtu => "packet exceeds MTU",
            VirtioNetError::InvalidHeader => "invalid virtio net header",
            VirtioNetError::DescriptorOutOfBounds => "descriptor out of bounds",
            VirtioNetError::DescriptorChainTooLong => "descriptor chain too long",
            VirtioNetError::InvalidDmaAddress => "invalid DMA address",
            VirtioNetError::RateLimitExceeded => "rate limit exceeded",
            VirtioNetError::NoBuffersAvailable => "no buffers available",
            VirtioNetError::NoDescriptorsAvailable => "no descriptors available",
            VirtioNetError::QueueError => "queue error",
            VirtioNetError::InvalidMacAddress => "invalid MAC address",
            VirtioNetError::MalformedPacket => "malformed packet",
            VirtioNetError::ChecksumError => "checksum error",
            VirtioNetError::DeviceNotReady => "device not ready",
            VirtioNetError::BufferTooSmall => "buffer too small",
            VirtioNetError::InitializationFailed => "initialization failed",
            VirtioNetError::FeatureNegotiationFailed => "feature negotiation failed",
            VirtioNetError::MsixConfigurationFailed => "MSI-X configuration failed",
            VirtioNetError::QueueSetupFailed => "queue setup failed",
            VirtioNetError::AllocationFailed => "memory allocation failed",
            VirtioNetError::GenericError => "generic error",
        }
    }

    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            VirtioNetError::RateLimitExceeded
                | VirtioNetError::InvalidMacAddress
                | VirtioNetError::MalformedPacket
                | VirtioNetError::InvalidHeader
                | VirtioNetError::DescriptorOutOfBounds
                | VirtioNetError::DescriptorChainTooLong
        )
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VirtioNetError::InvalidPacketSize
                | VirtioNetError::PacketTooSmall
                | VirtioNetError::PacketExceedsMtu
                | VirtioNetError::InvalidHeader
                | VirtioNetError::RateLimitExceeded
                | VirtioNetError::NoBuffersAvailable
                | VirtioNetError::NoDescriptorsAvailable
                | VirtioNetError::InvalidMacAddress
                | VirtioNetError::MalformedPacket
                | VirtioNetError::ChecksumError
                | VirtioNetError::BufferTooSmall
        )
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            VirtioNetError::DescriptorOutOfBounds
                | VirtioNetError::InvalidDmaAddress
                | VirtioNetError::QueueError
                | VirtioNetError::DeviceNotReady
                | VirtioNetError::InitializationFailed
                | VirtioNetError::FeatureNegotiationFailed
                | VirtioNetError::QueueSetupFailed
        )
    }

    pub fn category(&self) -> ErrorCategory {
        match self {
            VirtioNetError::InvalidPacketSize
            | VirtioNetError::PacketTooSmall
            | VirtioNetError::PacketExceedsMtu => ErrorCategory::PacketSize,

            VirtioNetError::InvalidHeader
            | VirtioNetError::MalformedPacket
            | VirtioNetError::ChecksumError => ErrorCategory::PacketFormat,

            VirtioNetError::DescriptorOutOfBounds
            | VirtioNetError::DescriptorChainTooLong
            | VirtioNetError::NoDescriptorsAvailable
            | VirtioNetError::QueueError => ErrorCategory::Descriptor,

            VirtioNetError::InvalidDmaAddress
            | VirtioNetError::NoBuffersAvailable
            | VirtioNetError::BufferTooSmall
            | VirtioNetError::AllocationFailed => ErrorCategory::Memory,

            VirtioNetError::RateLimitExceeded
            | VirtioNetError::InvalidMacAddress => ErrorCategory::Security,

            VirtioNetError::DeviceNotReady
            | VirtioNetError::InitializationFailed
            | VirtioNetError::FeatureNegotiationFailed
            | VirtioNetError::MsixConfigurationFailed
            | VirtioNetError::QueueSetupFailed => ErrorCategory::Device,

            VirtioNetError::GenericError => ErrorCategory::Other,
        }
    }
}

impl fmt::Display for VirtioNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    PacketSize,
    PacketFormat,
    Descriptor,
    Memory,
    Security,
    Device,
    Other,
}

impl ErrorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCategory::PacketSize => "packet_size",
            ErrorCategory::PacketFormat => "packet_format",
            ErrorCategory::Descriptor => "descriptor",
            ErrorCategory::Memory => "memory",
            ErrorCategory::Security => "security",
            ErrorCategory::Device => "device",
            ErrorCategory::Other => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_as_str() {
        assert_eq!(VirtioNetError::PacketTooSmall.as_str(), "packet too small");
        assert_eq!(VirtioNetError::RateLimitExceeded.as_str(), "rate limit exceeded");
    }

    #[test]
    fn test_is_security_relevant() {
        assert!(VirtioNetError::RateLimitExceeded.is_security_relevant());
        assert!(VirtioNetError::InvalidMacAddress.is_security_relevant());
        assert!(!VirtioNetError::BufferTooSmall.is_security_relevant());
    }

    #[test]
    fn test_is_recoverable() {
        assert!(VirtioNetError::PacketTooSmall.is_recoverable());
        assert!(VirtioNetError::NoBuffersAvailable.is_recoverable());
        assert!(!VirtioNetError::QueueError.is_recoverable());
    }

    #[test]
    fn test_is_fatal() {
        assert!(VirtioNetError::DescriptorOutOfBounds.is_fatal());
        assert!(VirtioNetError::QueueError.is_fatal());
        assert!(!VirtioNetError::PacketTooSmall.is_fatal());
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(VirtioNetError::PacketTooSmall.category(), ErrorCategory::PacketSize);
        assert_eq!(VirtioNetError::RateLimitExceeded.category(), ErrorCategory::Security);
        assert_eq!(VirtioNetError::QueueError.category(), ErrorCategory::Descriptor);
    }
}
