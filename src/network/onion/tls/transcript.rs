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

use super::crypto_provider::crypto;
use super::types::CipherSuite;
use alloc::vec::Vec;

pub(super) struct Transcript {
    state: [u8; 48],
    hash_len: usize,
    buffer: Vec<u8>,
}

impl Transcript {
    pub(super) fn new() -> Self {
        Self {
            state: [0u8; 48],
            hash_len: 32, // default SHA-256
            buffer: Vec::new(),
        }
    }

    /// Set the hash algorithm based on the negotiated cipher suite.
    pub(super) fn set_suite(&mut self, suite: CipherSuite) {
        self.hash_len = suite.hash_len();
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
        let c = crypto();
        if self.hash_len == 48 {
            let mut h = [0u8; 48];
            c.sha384(&self.buffer, &mut h);
            self.state = h;
        } else {
            let mut h = [0u8; 32];
            c.sha256(&self.buffer, &mut h);
            self.state[..32].copy_from_slice(&h);
            self.state[32..].fill(0);
        }
    }

    /// Returns the transcript hash, length determined by `hash_len`.
    pub(super) fn hash(&self) -> &[u8] {
        &self.state[..self.hash_len]
    }

    /// RFC 8446 §4.4.1: Replace transcript with synthetic message_hash construct.
    /// Called after receiving HelloRetryRequest, before adding HRR to transcript.
    ///
    /// The current hash (Hash(CH1)) is wrapped in a synthetic handshake message:
    ///   message_hash(254) || 00 00 hash_len || Hash(CH1)
    /// Then the transcript buffer is replaced and re-hashed.
    pub(super) fn replace_with_message_hash(&mut self) {
        let hl = self.hash_len;
        let hash: [u8; 48] = self.state;
        self.buffer.clear();
        self.buffer.push(254); // message_hash handshake type
        self.buffer.push(0);
        self.buffer.push(0);
        self.buffer.push(hl as u8);
        self.buffer.extend_from_slice(&hash[..hl]);
        self.update();
    }
}
