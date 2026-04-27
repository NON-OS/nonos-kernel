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

pub struct ProofAggregator {
    pub(super) challenge_seed: [u8; 32],
}

impl ProofAggregator {
    pub fn new() -> Self {
        Self { challenge_seed: [0u8; 32] }
    }

    pub fn set_challenge_seed(&mut self, seed: [u8; 32]) {
        self.challenge_seed = seed;
    }
}

impl Default for ProofAggregator {
    fn default() -> Self {
        Self::new()
    }
}
