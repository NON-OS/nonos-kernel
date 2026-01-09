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
pub enum NetworkError {
    NoInterface,
    InterfaceDown,
    LinkDown,
    InvalidAddress,
    InvalidPort,
    AddressInUse,
    ConnectionRefused,
    ConnectionReset,
    ConnectionTimeout,
    NotConnected,
    AlreadyConnected,
    BufferTooSmall,
    PacketTooLarge,
    InvalidPacket,
    ChecksumError,
    RoutingError,
    NoRoute,
    Unreachable,
    TxQueueFull,
    RxQueueEmpty,
    SocketError,
    ProtocolError,
    ArpTimeout,
    DnsError,
    TlsError,
}

impl NetworkError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoInterface => "No network interface available",
            Self::InterfaceDown => "Network interface is down",
            Self::LinkDown => "Network link is down",
            Self::InvalidAddress => "Invalid network address",
            Self::InvalidPort => "Invalid port number",
            Self::AddressInUse => "Address already in use",
            Self::ConnectionRefused => "Connection refused",
            Self::ConnectionReset => "Connection reset by peer",
            Self::ConnectionTimeout => "Connection timed out",
            Self::NotConnected => "Not connected",
            Self::AlreadyConnected => "Already connected",
            Self::BufferTooSmall => "Buffer too small",
            Self::PacketTooLarge => "Packet too large",
            Self::InvalidPacket => "Invalid packet",
            Self::ChecksumError => "Checksum error",
            Self::RoutingError => "Routing error",
            Self::NoRoute => "No route to host",
            Self::Unreachable => "Host unreachable",
            Self::TxQueueFull => "Transmit queue full",
            Self::RxQueueEmpty => "Receive queue empty",
            Self::SocketError => "Socket error",
            Self::ProtocolError => "Protocol error",
            Self::ArpTimeout => "ARP resolution timeout",
            Self::DnsError => "DNS resolution error",
            Self::TlsError => "TLS error",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::TxQueueFull
                | Self::RxQueueEmpty
                | Self::ConnectionTimeout
                | Self::ArpTimeout
        )
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, NetworkError>;
