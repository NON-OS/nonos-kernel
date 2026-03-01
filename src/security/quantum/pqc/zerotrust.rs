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
use alloc::collections::BTreeMap;
use spin::Mutex;

pub struct QuantumZeroTrust {
    trust_scores: Mutex<BTreeMap<[u8; 32], u8>>,
}

impl QuantumZeroTrust {
    pub fn new() -> Self {
        Self {
            trust_scores: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn set_trust(&self, key_id: [u8; 32], score: u8) {
        self.trust_scores.lock().insert(key_id, score);
    }

    pub fn verify(&self, key_id: [u8; 32], min_score: u8) -> bool {
        self.trust_scores.lock().get(&key_id).map_or(false, |&score| score >= min_score)
    }
}
