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


use alloc::vec::Vec;
use spin::Mutex;
use crate::network::onion::OnionError;
use super::types::CircuitId;

pub(super) struct CircuitPool {
    pub prebuilt_circuits: Mutex<Vec<CircuitId>>,
    pub pool_size: usize,
    pub min_circuits: usize,
}

impl CircuitPool {
    pub(super) fn new(pool_size: usize, min_circuits: usize) -> Self {
        Self {
            prebuilt_circuits: Mutex::new(Vec::new()),
            pool_size,
            min_circuits,
        }
    }

    pub(super) fn init(&self) -> Result<(), OnionError> {
        Ok(())
    }

    pub(super) fn maybe_add(&self, id: CircuitId) {
        let mut v = self.prebuilt_circuits.lock();
        if v.len() < self.pool_size {
            v.push(id);
        }
    }
}
