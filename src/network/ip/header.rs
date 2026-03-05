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

//! IP header structures

/// IPv4 header
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub ttl: u8,
    pub protocol: u8,
    pub total_length: u16,
    pub header_length: u8,
}

impl Ipv4Header {
    /// Minimum header size (no options)
    pub const MIN_SIZE: usize = 20;

    /// Maximum header size (with options)
    pub const MAX_SIZE: usize = 60;
}

/// IPv6 header
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub hop_limit: u8,
    pub next_header: u8,
    pub payload_length: u16,
}

impl Ipv6Header {
    /// Fixed header size
    pub const SIZE: usize = 40;
}
