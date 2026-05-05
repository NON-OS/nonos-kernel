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

// Capsule entropy pool.
//
// The capsule is the userland-owned routing point for random bytes:
// every `GetRandom` request resolves through `crypto_random` (the
// kernel boot RNG, the trusted source) and the pool accounts
// requests/bytes/source-failures plus a reseed counter for
// observability. Userland callers never call `crypto_random`
// directly — they go through the capsule's IPC surface, where the
// CAP_ENTROPY check enforces authority.

use core::sync::atomic::{AtomicU64, Ordering};

use nonos_libc::crypto_random;

use crate::protocol::MAX_RANDOM_BYTES;

#[repr(C)]
pub struct Stats {
    pub uptime_requests: u64,
    pub bytes_served: u64,
    pub last_reseed_request: u64,
    pub source_failures: u64,
}

pub struct Pool {
    requests: AtomicU64,
    bytes_served: AtomicU64,
    last_reseed_request: AtomicU64,
    source_failures: AtomicU64,
}

impl Pool {
    pub const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            bytes_served: AtomicU64::new(0),
            last_reseed_request: AtomicU64::new(0),
            source_failures: AtomicU64::new(0),
        }
    }

    // Fill `out` with random bytes. Returns the count actually written;
    // negative on hard failure. Does not panic on short reads — callers
    // map any short return to EIO.
    pub fn fill(&self, out: &mut [u8]) -> i64 {
        let cap = MAX_RANDOM_BYTES as usize;
        let want = if out.len() > cap { cap } else { out.len() };
        if want == 0 {
            return 0;
        }
        let n = crypto_random(out.as_mut_ptr(), want);
        self.requests.fetch_add(1, Ordering::Relaxed);
        if n < 0 {
            self.source_failures.fetch_add(1, Ordering::Relaxed);
            return n;
        }
        self.bytes_served.fetch_add(n as u64, Ordering::Relaxed);
        n
    }

    // Record a reseed request. Counted for observability; the routed
    // RNG itself is owned by the kernel so there is no userland mixer
    // state to drive.
    pub fn record_reseed(&self) {
        self.last_reseed_request.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Stats {
        Stats {
            uptime_requests: self.requests.load(Ordering::Relaxed),
            bytes_served: self.bytes_served.load(Ordering::Relaxed),
            last_reseed_request: self.last_reseed_request.load(Ordering::Relaxed),
            source_failures: self.source_failures.load(Ordering::Relaxed),
        }
    }
}

pub fn encode_stats(s: &Stats) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&s.uptime_requests.to_le_bytes());
    out[8..16].copy_from_slice(&s.bytes_served.to_le_bytes());
    out[16..24].copy_from_slice(&s.last_reseed_request.to_le_bytes());
    out[24..32].copy_from_slice(&s.source_failures.to_le_bytes());
    out
}
