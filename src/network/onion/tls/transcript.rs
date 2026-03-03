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
use super::crypto_provider::crypto;

pub(super) struct Transcript {
    state: [u8; 32],
    buffer: Vec<u8>,
}

impl Transcript {
    pub(super) fn new() -> Self {
        Self {
            state: [0u8; 32],
            buffer: Vec::new(),
        }
    }

    pub(super) fn add_handshake(&mut self, hs: &[u8]) {
        self.buffer.extend_from_slice(hs);
        self.update();
    }

    pub(super) fn add_raw(&mut self, raw: &[u8]) {
        self.buffer.extend_from_slice(raw);
        self.update();
    }

    fn update(&mut self) {
        crypto().sha256(&self.buffer, &mut self.state);
    }

    pub(super) fn hash(&self) -> &[u8; 32] {
        &self.state
    }
}
