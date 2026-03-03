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


use core::sync::atomic::AtomicU64;
use crate::network::stack::TcpSocket;
use crate::network::ip::IpAddress;
use super::types::{ConnectionState, TlsConnectionState};
use super::limiter::DirectionLimiters;

pub struct AnyoneConnection {
    pub id: u32,
    pub socket: TcpSocket,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
    pub local_port: u16,
    pub state: ConnectionState,
    pub created_at_ms: u64,
    pub last_activity_ms: u64,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub tls: Option<TlsConnectionState>,
    pub updown: Option<DirectionLimiters>,
}
