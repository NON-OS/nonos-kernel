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

use super::connection::{connect_to_gateway, GatewayConnection};
use crate::network::nym::error::NymError;
use crate::network::nym::types::{ClientId, Gateway, GatewayId};
use alloc::collections::BTreeMap;
use spin::{Mutex, Once};

static GATEWAY_POOL: Once<Mutex<GatewayPool>> = Once::new();

pub struct GatewayPool {
    connections: BTreeMap<GatewayId, GatewayConnection>,
    max_connections: usize,
}

pub fn get_gateway_pool() -> &'static Mutex<GatewayPool> {
    GATEWAY_POOL.call_once(|| Mutex::new(GatewayPool::new(8)))
}

impl GatewayPool {
    pub fn new(max_connections: usize) -> Self {
        Self { connections: BTreeMap::new(), max_connections }
    }

    pub fn get_or_connect(
        &mut self,
        gateway: &Gateway,
        client_id: &ClientId,
    ) -> Result<&GatewayConnection, NymError> {
        if !self.connections.contains_key(&gateway.id) {
            if self.connections.len() >= self.max_connections {
                self.evict_oldest();
            }
            let conn = connect_to_gateway(gateway, client_id)?;
            self.connections.insert(gateway.id, conn);
        }
        self.connections.get(&gateway.id).ok_or(NymError::GatewayNotFound)
    }

    pub fn remove(&mut self, gateway_id: &GatewayId) {
        if let Some(mut conn) = self.connections.remove(gateway_id) {
            conn.close();
        }
    }

    pub fn close_all(&mut self) {
        let keys: alloc::vec::Vec<_> = self.connections.keys().copied().collect();
        for key in keys {
            if let Some(mut conn) = self.connections.remove(&key) {
                conn.close();
            }
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_id) = self.connections.keys().next().copied() {
            self.remove(&oldest_id);
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}
