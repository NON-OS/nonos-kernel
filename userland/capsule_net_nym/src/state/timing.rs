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

use core::sync::atomic::{AtomicU16, Ordering};

static COVER_BURST: AtomicU16 = AtomicU16::new(1);
static DELAY_JITTER_MS: AtomicU16 = AtomicU16::new(250);

#[derive(Clone, Copy)]
pub struct TimingPolicy {
    pub cover_burst: u16,
    pub delay_jitter_ms: u16,
}

pub fn install(body: &[u8]) -> bool {
    if body.len() != 4 {
        return false;
    }
    let burst = u16::from_le_bytes([body[0], body[1]]).clamp(1, 8);
    let jitter = u16::from_le_bytes([body[2], body[3]]).clamp(10, 10_000);
    COVER_BURST.store(burst, Ordering::Release);
    DELAY_JITTER_MS.store(jitter, Ordering::Release);
    true
}

pub fn policy() -> TimingPolicy {
    TimingPolicy {
        cover_burst: COVER_BURST.load(Ordering::Acquire),
        delay_jitter_ms: DELAY_JITTER_MS.load(Ordering::Acquire),
    }
}
