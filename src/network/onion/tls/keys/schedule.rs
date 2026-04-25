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

use super::super::types::CipherSuite;
use super::secret::Secret;

pub(crate) struct KeySchedule {
    pub early_prk: [u8; 48],
    pub handshake_prk: [u8; 48],
    pub master_prk: [u8; 48],
    pub client_hs: Secret,
    pub server_hs: Secret,
    pub client_app: Secret,
    pub server_app: Secret,
    pub(super) hash_len: usize,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        for b in self.early_prk.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in self.handshake_prk.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in self.master_prk.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl KeySchedule {
    pub(crate) fn new() -> Self {
        Self {
            early_prk: [0u8; 48],
            handshake_prk: [0u8; 48],
            master_prk: [0u8; 48],
            client_hs: Secret::new(32),
            server_hs: Secret::new(32),
            client_app: Secret::new(32),
            server_app: Secret::new(32),
            hash_len: 32,
        }
    }
    pub(crate) fn set_suite(&mut self, suite: CipherSuite) {
        self.hash_len = suite.hash_len();
        self.client_hs.len = self.hash_len;
        self.server_hs.len = self.hash_len;
        self.client_app.len = self.hash_len;
        self.server_app.len = self.hash_len;
    }
}
