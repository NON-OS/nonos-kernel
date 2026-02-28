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

use crate::arch::x86_64::keyboard::input::error::{InputError, InputErrorCode, InputResult};

pub const DEFAULT_MAX_QUEUE_SIZE: usize = 256;
pub const MAX_ALLOWED_QUEUE_SIZE: usize = 65536;
pub const DEFAULT_PRESSURE_THRESHOLD: usize = 192;
pub const MAX_COALESCE_COUNT: usize = 16;

#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub max_size: usize,
    pub pressure_threshold: usize,
    pub coalesce_mouse_moves: bool,
    pub max_coalesce_count: usize,
    pub drop_low_priority_under_pressure: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_QUEUE_SIZE,
            pressure_threshold: DEFAULT_PRESSURE_THRESHOLD,
            coalesce_mouse_moves: true,
            max_coalesce_count: MAX_COALESCE_COUNT,
            drop_low_priority_under_pressure: true,
        }
    }
}

impl QueueConfig {
    pub fn validate(&self) -> InputResult<()> {
        if self.max_size == 0 {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "max_size cannot be zero",
            ));
        }
        if self.max_size > MAX_ALLOWED_QUEUE_SIZE {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                alloc::format!("max_size exceeds limit of {}", MAX_ALLOWED_QUEUE_SIZE),
            ));
        }
        if self.pressure_threshold >= self.max_size {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "pressure_threshold must be less than max_size",
            ));
        }
        Ok(())
    }
}
