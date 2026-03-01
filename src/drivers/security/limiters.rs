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

use super::constants::{DEFAULT_ADMIN_OPS_PER_SEC, DEFAULT_DMA_OPS_PER_SEC, DEFAULT_IO_OPS_PER_SEC};
use super::rate_limiter::{MultiRateLimiter, RateLimiter};

pub const fn io_rate_limiter() -> RateLimiter {
    RateLimiter::new(DEFAULT_IO_OPS_PER_SEC)
}

pub const fn admin_rate_limiter() -> RateLimiter {
    RateLimiter::new(DEFAULT_ADMIN_OPS_PER_SEC)
}

pub const fn dma_rate_limiter() -> RateLimiter {
    RateLimiter::new(DEFAULT_DMA_OPS_PER_SEC)
}

pub const fn default_multi_rate_limiter() -> MultiRateLimiter {
    MultiRateLimiter::new(
        DEFAULT_IO_OPS_PER_SEC,
        DEFAULT_ADMIN_OPS_PER_SEC,
        DEFAULT_DMA_OPS_PER_SEC,
    )
}
