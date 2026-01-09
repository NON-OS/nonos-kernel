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
pub enum E1000Error {
    DeviceNotFound,
    InitializationFailed,
    InvalidBar,
    EepromTimeout,
    EepromReadFailed,
    LinkDown,
    TxQueueFull,
    TxTimeout,
    RxBufferEmpty,
    InvalidPacketSize,
    DmaAllocationFailed,
    InvalidMtu,
    PhyError,
    ResetFailed,
    InterruptError,
}

impl E1000Error {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceNotFound => "E1000 device not found",
            Self::InitializationFailed => "E1000 initialization failed",
            Self::InvalidBar => "Invalid BAR configuration",
            Self::EepromTimeout => "EEPROM read timeout",
            Self::EepromReadFailed => "EEPROM read failed",
            Self::LinkDown => "Network link is down",
            Self::TxQueueFull => "Transmit queue full",
            Self::TxTimeout => "Transmit timeout",
            Self::RxBufferEmpty => "Receive buffer empty",
            Self::InvalidPacketSize => "Invalid packet size",
            Self::DmaAllocationFailed => "DMA buffer allocation failed",
            Self::InvalidMtu => "Invalid MTU value",
            Self::PhyError => "PHY communication error",
            Self::ResetFailed => "Device reset failed",
            Self::InterruptError => "Interrupt configuration error",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::TxQueueFull | Self::RxBufferEmpty | Self::LinkDown | Self::TxTimeout
        )
    }
}

impl fmt::Display for E1000Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, E1000Error>;
