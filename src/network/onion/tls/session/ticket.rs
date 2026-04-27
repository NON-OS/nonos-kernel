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

use super::consts::MAX_TICKET_LIFETIME_SECS;
use crate::network::onion::tls::keys::expand_label_len;
use crate::network::onion::tls::types::CipherSuite;
use alloc::vec;
use alloc::vec::Vec;

pub struct SessionTicket {
    pub ticket: Vec<u8>,
    pub lifetime_secs: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub resumption_secret: Vec<u8>,
    pub suite: CipherSuite,
    pub hash_len: usize,
    pub created_ms: u64,
    pub max_early_data: u32,
}

impl SessionTicket {
    pub fn derive_psk(&self) -> Vec<u8> {
        let mut psk = vec![0u8; self.hash_len];
        expand_label_len(
            &self.resumption_secret,
            b"resumption",
            &self.nonce,
            &mut psk,
            self.hash_len,
        );
        psk
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        let effective_lifetime = self.lifetime_secs.min(MAX_TICKET_LIFETIME_SECS);
        let expiry_ms = self.created_ms.saturating_add(effective_lifetime as u64 * 1000);
        now_ms >= expiry_ms
    }

    pub fn obfuscated_age(&self, now_ms: u64) -> u32 {
        let real_age_ms = now_ms.saturating_sub(self.created_ms) as u32;
        real_age_ms.wrapping_add(self.age_add)
    }
}

impl Drop for SessionTicket {
    fn drop(&mut self) {
        for byte in self.resumption_secret.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.nonce.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.ticket.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
