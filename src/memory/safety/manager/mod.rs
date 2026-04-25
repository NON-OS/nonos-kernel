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

mod api;
mod corruption;
mod detector;
mod guards;
mod helpers;
mod patterns;
mod safe_ops;
mod stack_verify;
mod state;
mod stats;
mod validate;

pub use api::{init, set_protection_level, validate_execute, validate_read, validate_write};
pub use guards::get_guard_regions;
pub use safe_ops::{safe_copy, safe_zero};
pub use stack_verify::verify_stack_integrity;
pub use state::REGIONS;
pub use stats::{check_integrity, get_stats, last_corruption_check};
