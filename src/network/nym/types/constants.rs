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

pub const NYM_PACKET_SIZE: usize = 2048;
pub const NYM_PAYLOAD_SIZE: usize = 1024;
pub const NYM_HEADER_SIZE: usize = 816;
pub const NYM_MAC_SIZE: usize = 16;
pub const NYM_ROUTING_INFO_SIZE: usize = 32;
pub const NYM_MIX_LAYERS: usize = 3;
pub const NYM_COVER_INTERVAL_MS: u64 = 100;
pub const NYM_KEY_SIZE: usize = 32;
pub const NYM_NONCE_SIZE: usize = 12;
pub const NYM_TAG_SIZE: usize = 16;
pub const NYM_NODE_ADDRESS_SIZE: usize = 32;
pub const NYM_SURB_SIZE: usize = 296;
pub const NYM_FRAGMENT_SIZE: usize = 500;
pub const NYM_MAX_HOPS: usize = 5;
pub const NYM_DEFAULT_GATEWAY_PORT: u16 = 9000;
pub const NYM_DEFAULT_MIX_PORT: u16 = 1789;
pub const NYM_CONNECT_TIMEOUT_MS: u64 = 15000;
pub const NYM_READ_TIMEOUT_MS: u64 = 5000;
pub const NYM_WRITE_TIMEOUT_MS: u64 = 10000;
