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


use core::sync::atomic::{AtomicU32, Ordering};

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn next_id() -> u32 {
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Clone)]
pub struct TcpSocket {
    id: u32,
    pub remote_port: u16,
    pub local_port: u16,
}

impl TcpSocket {
    pub fn new() -> Self {
        Self {
            id: next_id(),
            remote_port: 0,
            local_port: 0,
        }
    }

    pub fn connection_id(&self) -> u32 {
        self.id
    }

    pub fn from_connection(id: u32) -> Self {
        Self {
            id,
            remote_port: 0,
            local_port: 0,
        }
    }

    pub fn with_ports(local_port: u16, remote_port: u16) -> Self {
        Self {
            id: next_id(),
            local_port,
            remote_port,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.id != 0
    }
}

impl Default for TcpSocket {
    fn default() -> Self {
        Self::new()
    }
}
