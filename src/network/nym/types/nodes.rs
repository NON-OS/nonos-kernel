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

extern crate alloc;

use super::ids::{GatewayId, MixNodeId};
use alloc::string::String;

#[derive(Clone, Debug)]
pub struct MixNode {
    pub id: MixNodeId,
    pub identity_key: [u8; 32],
    pub sphinx_key: [u8; 32],
    pub host: String,
    pub mix_port: u16,
    pub layer: u8,
    pub version: String,
    pub stake: u64,
    pub performance: u8,
}

#[derive(Clone, Debug)]
pub struct Gateway {
    pub id: GatewayId,
    pub identity_key: [u8; 32],
    pub sphinx_key: [u8; 32],
    pub host: String,
    pub mix_port: u16,
    pub clients_port: u16,
    pub version: String,
    pub stake: u64,
}

impl MixNode {
    pub fn is_healthy(&self) -> bool {
        self.performance >= 50 && self.stake > 0
    }
}

impl Gateway {
    pub fn is_healthy(&self) -> bool {
        self.stake > 0
    }
}
