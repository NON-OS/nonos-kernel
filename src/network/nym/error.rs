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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NymError {
    NotInitialized,
    AlreadyInitialized,
    ConnectionFailed,
    GatewayNotFound,
    MixNodeNotFound,
    InvalidRoute,
    InvalidPacket,
    PacketTooLarge,
    EncryptionFailed,
    DecryptionFailed,
    InvalidMac,
    InvalidHeader,
    InvalidPayload,
    InvalidSurb,
    NoAvailableMixNodes,
    NoAvailableGateways,
    DirectoryFetchFailed,
    Timeout,
    SocketError,
    TlsError,
    InvalidAddress,
    StreamClosed,
    BufferFull,
    InternalError,
}

impl NymError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "NYM client not initialized",
            Self::AlreadyInitialized => "NYM client already initialized",
            Self::ConnectionFailed => "Failed to connect to gateway",
            Self::GatewayNotFound => "Gateway not found",
            Self::MixNodeNotFound => "MixNode not found",
            Self::InvalidRoute => "Invalid route through mixnet",
            Self::InvalidPacket => "Invalid Sphinx packet",
            Self::PacketTooLarge => "Packet payload too large",
            Self::EncryptionFailed => "Sphinx encryption failed",
            Self::DecryptionFailed => "Sphinx decryption failed",
            Self::InvalidMac => "Invalid MAC on packet",
            Self::InvalidHeader => "Invalid Sphinx header",
            Self::InvalidPayload => "Invalid packet payload",
            Self::InvalidSurb => "Invalid SURB",
            Self::NoAvailableMixNodes => "No available mixnodes",
            Self::NoAvailableGateways => "No available gateways",
            Self::DirectoryFetchFailed => "Failed to fetch directory",
            Self::Timeout => "Operation timed out",
            Self::SocketError => "Socket operation failed",
            Self::TlsError => "TLS error",
            Self::InvalidAddress => "Invalid NYM address",
            Self::StreamClosed => "Stream is closed",
            Self::BufferFull => "Buffer is full",
            Self::InternalError => "Internal error",
        }
    }
}
