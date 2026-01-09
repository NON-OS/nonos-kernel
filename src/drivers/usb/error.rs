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
pub enum UsbError {
    ControllerNotFound,
    InitializationFailed,
    DeviceNotFound,
    EndpointNotFound,
    TransferFailed,
    TransferTimeout,
    TransferStall,
    TransferBabble,
    BufferOverrun,
    BufferUnderrun,
    InvalidDescriptor,
    InvalidConfiguration,
    InvalidInterface,
    InvalidEndpoint,
    UnsupportedDevice,
    UnsupportedClass,
    PortError,
    ResetFailed,
    EnumerationFailed,
    DmaError,
    CommandRingFull,
    EventRingEmpty,
    SlotNotEnabled,
    ContextError,
}

impl UsbError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ControllerNotFound => "USB controller not found",
            Self::InitializationFailed => "USB initialization failed",
            Self::DeviceNotFound => "USB device not found",
            Self::EndpointNotFound => "Endpoint not found",
            Self::TransferFailed => "Transfer failed",
            Self::TransferTimeout => "Transfer timeout",
            Self::TransferStall => "Endpoint stalled",
            Self::TransferBabble => "Babble detected",
            Self::BufferOverrun => "Buffer overrun",
            Self::BufferUnderrun => "Buffer underrun",
            Self::InvalidDescriptor => "Invalid descriptor",
            Self::InvalidConfiguration => "Invalid configuration",
            Self::InvalidInterface => "Invalid interface",
            Self::InvalidEndpoint => "Invalid endpoint",
            Self::UnsupportedDevice => "Unsupported device",
            Self::UnsupportedClass => "Unsupported device class",
            Self::PortError => "Port error",
            Self::ResetFailed => "Device reset failed",
            Self::EnumerationFailed => "Device enumeration failed",
            Self::DmaError => "DMA error",
            Self::CommandRingFull => "Command ring full",
            Self::EventRingEmpty => "Event ring empty",
            Self::SlotNotEnabled => "Slot not enabled",
            Self::ContextError => "Context error",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::TransferTimeout
                | Self::TransferStall
                | Self::CommandRingFull
                | Self::EventRingEmpty
        )
    }
}

impl fmt::Display for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, UsbError>;
