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


#[derive(Debug)]
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_per_ms: u64,
    last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new(bytes_per_sec: u64, now_ms: u64) -> Self {
        let cap = if bytes_per_sec == 0 { 1 } else { bytes_per_sec };
        let per_ms = core::cmp::max(1, cap / 1000);
        Self {
            capacity: cap,
            tokens: cap,
            refill_per_ms: per_ms,
            last_refill_ms: now_ms,
        }
    }

    pub fn set_rate(&mut self, bytes_per_sec: u64, now_ms: u64) {
        self.refill(now_ms);
        self.capacity = if bytes_per_sec == 0 { 1 } else { bytes_per_sec };
        self.tokens = core::cmp::min(self.tokens, self.capacity);
        self.refill_per_ms = core::cmp::max(1, self.capacity / 1000);
    }

    pub fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_refill_ms {
            return;
        }
        let delta = now_ms - self.last_refill_ms;
        let add = delta.saturating_mul(self.refill_per_ms);
        self.tokens = core::cmp::min(self.capacity, self.tokens.saturating_add(add));
        self.last_refill_ms = now_ms;
    }

    pub fn try_consume(&mut self, n: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct DirectionLimiters {
    pub up: TokenBucket,
    pub down: TokenBucket,
}
