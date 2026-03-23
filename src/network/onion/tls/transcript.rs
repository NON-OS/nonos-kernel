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

    /// RFC 8446 §4.4.1: Replace transcript with synthetic message_hash construct.
    /// Called after receiving HelloRetryRequest, before adding HRR to transcript.
    ///
    /// The current hash (Hash(CH1)) is wrapped in a synthetic handshake message:
    ///   message_hash(254) || 00 00 hash_len || Hash(CH1)
    /// Then the transcript buffer is replaced and re-hashed.
    pub(super) fn replace_with_message_hash(&mut self) {
        let hash = self.state;
        self.buffer.clear();
        self.buffer.push(254); // message_hash handshake type
        self.buffer.push(0);
        self.buffer.push(0);
        self.buffer.push(32); // SHA-256 hash length
        self.buffer.extend_from_slice(&hash);
        self.update();
    }
}
