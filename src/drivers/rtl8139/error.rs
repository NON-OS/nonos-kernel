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
pub enum Rtl8139Error {
    DeviceNotFound,
    InitializationFailed,
    InvalidBar,
    ResetTimeout,
    TxQueueFull,
    TxTimeout,
    RxBufferOverflow,
    InvalidPacketSize,
    DmaAllocationFailed,
    LinkDown,
    CrcError,
    FrameAlignmentError,
    RuntPacket,
    LongPacket,
    FifoError,
}

impl Rtl8139Error {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceNotFound => "RTL8139 device not found",
            Self::InitializationFailed => "RTL8139 initialization failed",
            Self::InvalidBar => "Invalid BAR configuration",
            Self::ResetTimeout => "Device reset timeout",
            Self::TxQueueFull => "Transmit queue full",
            Self::TxTimeout => "Transmit timeout",
            Self::RxBufferOverflow => "Receive buffer overflow",
            Self::InvalidPacketSize => "Invalid packet size",
            Self::DmaAllocationFailed => "DMA buffer allocation failed",
            Self::LinkDown => "Network link is down",
            Self::CrcError => "CRC error in received packet",
            Self::FrameAlignmentError => "Frame alignment error",
            Self::RuntPacket => "Runt packet received",
            Self::LongPacket => "Packet too long",
            Self::FifoError => "FIFO error",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::TxQueueFull | Self::RxBufferOverflow | Self::LinkDown | Self::TxTimeout
        )
    }
}

impl fmt::Display for Rtl8139Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, Rtl8139Error>;
