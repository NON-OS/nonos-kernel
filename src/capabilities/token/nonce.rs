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

use core::sync::atomic::{AtomicU64, Ordering};

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[inline]
pub fn default_nonce() -> u64 {
    let mut buf = [0u8; 8];
    if crate::crypto::random_api::get_bytes_secure(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        let timestamp = crate::time::timestamp_millis();
        let counter = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        timestamp.wrapping_mul(0x9E3779B97F4A7C15) ^ counter
    }
}

#[inline]
pub(crate) fn secure_nonce_128() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let _ = crate::crypto::random_api::get_bytes_secure(&mut buf);
    buf
}

#[inline]
pub fn reset_nonce_counter() {
    NONCE_COUNTER.store(1, Ordering::SeqCst);
}

#[inline]
pub fn current_nonce_counter() -> u64 {
    NONCE_COUNTER.load(Ordering::SeqCst)
}
