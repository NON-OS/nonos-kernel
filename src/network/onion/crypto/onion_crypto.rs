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


use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::network::onion::OnionError;
use super::layer_keys::LayerKeys;

#[derive(Debug)]
pub struct OnionCrypto {
    circuits: Mutex<BTreeMap<u32, Vec<LayerKeys>>>,
    operation_count: AtomicU64,
}

impl Clone for OnionCrypto {
    fn clone(&self) -> Self {
        Self {
            circuits: Mutex::new(BTreeMap::new()),
            operation_count: AtomicU64::new(self.operation_count.load(Ordering::Relaxed)),
        }
    }
}

impl OnionCrypto {
    pub fn new() -> Self {
        Self {
            circuits: Mutex::new(BTreeMap::new()),
            operation_count: AtomicU64::new(0),
        }
    }

    pub fn add_circuit(&self, circuit_id: u32, layers: Vec<LayerKeys>) {
        let mut map = self.circuits.lock();
        map.insert(circuit_id, layers);
    }

    pub fn remove_circuit(&self, circuit_id: u32) {
        let mut map = self.circuits.lock();
        map.remove(&circuit_id);
    }

    pub fn encrypt_forward(&self, circuit_id: u32, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut map = self.circuits.lock();
        if let Some(layers) = map.get_mut(&circuit_id) {
            let mut buf = data.to_vec();
            for layer in layers.iter_mut().rev() {
                buf = layer.encrypt_forward(&buf)?;
            }
            self.operation_count.fetch_add(1, Ordering::Relaxed);
            Ok(buf)
        } else {
            Err(OnionError::CircuitBuildFailed)
        }
    }

    pub fn decrypt_backward(&self, circuit_id: u32, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut map = self.circuits.lock();
        if let Some(layers) = map.get_mut(&circuit_id) {
            let mut buf = data.to_vec();
            for layer in layers.iter_mut() {
                buf = layer.decrypt_backward(&buf)?;
            }
            self.operation_count.fetch_add(1, Ordering::Relaxed);
            Ok(buf)
        } else {
            Err(OnionError::CircuitBuildFailed)
        }
    }

    pub fn get_stats(&self) -> u64 {
        self.operation_count.load(Ordering::Relaxed)
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.lock().len()
    }
}

impl Default for OnionCrypto {
    fn default() -> Self {
        Self::new()
    }
}
