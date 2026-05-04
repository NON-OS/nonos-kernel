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

use super::state::POOL;
use core::sync::atomic::{AtomicU64, Ordering};

static RESEED_COUNT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct EntropyStats {
    pub entropy_bits: u64,
    pub bytes_extracted: u64,
    pub bits_added: u64,
    pub reseed_count: u64,
}

pub(crate) fn get_stats() -> EntropyStats {
    let pool = POOL.lock();
    EntropyStats {
        entropy_bits: pool.entropy_bits,
        bytes_extracted: pool.bytes_extracted,
        bits_added: pool.bits_added,
        reseed_count: RESEED_COUNT.load(Ordering::Relaxed),
    }
}
