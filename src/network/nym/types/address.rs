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

use super::ids::{ClientId, GatewayId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NymAddress {
    pub gateway: GatewayId,
    pub client_id: ClientId,
}

impl NymAddress {
    pub fn new(gateway: GatewayId, client_id: ClientId) -> Self {
        Self { gateway, client_id }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.gateway.0);
        out[32..].copy_from_slice(&self.client_id.0);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        Some(Self {
            gateway: GatewayId::from_bytes(&bytes[..32])?,
            client_id: ClientId::from_bytes(&bytes[32..])?,
        })
    }
}
