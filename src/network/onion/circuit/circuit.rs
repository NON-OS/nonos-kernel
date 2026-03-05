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

//! Circuit structure and operations

use alloc::vec::Vec;
use crate::network::onion::OnionError;
use crate::network::onion::directory::RelayDescriptor;
use crate::network::onion::crypto::{LayerKeys, OnionCrypto};
use super::types::{CircuitId, CircuitState, CircuitHop, CircuitPurpose, PathConstraints};

#[derive(Debug, Clone)]
pub struct Circuit {
    pub id: CircuitId,
    pub state: CircuitState,
    pub hops: Vec<CircuitHop>,
    pub created_time: u64,
    pub last_activity: u64,
    pub purpose: CircuitPurpose,
    pub crypto: OnionCrypto,
    pub max_streams: u16,
    pub active_streams: u16,
    pub path_selection_constraints: PathConstraints,
}

impl Circuit {
    pub fn new(id: CircuitId, purpose: CircuitPurpose) -> Self {
        Self {
            id,
            state: CircuitState::Building,
            hops: Vec::new(),
            created_time: Self::now_ms(),
            last_activity: Self::now_ms(),
            purpose,
            crypto: OnionCrypto::new(),
            max_streams: 65535,
            active_streams: 0,
            path_selection_constraints: PathConstraints::default(),
        }
    }

    pub fn add_hop(&mut self, relay: RelayDescriptor, keys: LayerKeys) -> Result<(), OnionError> {
        if self.hops.len() >= 3 {
            return Err(OnionError::CircuitBuildFailed);
        }
        let hop = CircuitHop {
            relay,
            keys,
            extend_info: None,
            rtt_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };
        self.hops.push(hop);
        let layer_keys: Vec<LayerKeys> = self.hops.iter().map(|h| h.keys.clone()).collect();
        self.crypto.add_circuit(self.id, layer_keys);
        Ok(())
    }

    pub fn mark_open(&mut self) {
        self.state = CircuitState::Open;
        self.last_activity = Self::now_ms();
    }

    pub fn is_open(&self) -> bool {
        self.state == CircuitState::Open && self.hops.len() == 3
    }

    pub fn encrypt_forward(&self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        self.crypto.encrypt_forward(self.id, data)
    }

    pub fn decrypt_backward(&self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        self.crypto.decrypt_backward(self.id, data)
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn is_expired(&self, max_age_ms: u64) -> bool {
        Self::now_ms().saturating_sub(self.created_time) > max_age_ms
    }

    pub fn touch(&mut self) {
        self.last_activity = Self::now_ms();
    }

    #[inline]
    fn now_ms() -> u64 {
        crate::time::now_ns() / 1_000_000
    }
}
