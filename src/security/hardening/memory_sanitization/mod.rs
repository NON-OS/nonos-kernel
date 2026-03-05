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

pub mod types;
pub mod state;
pub mod primitives;
pub mod erase;
pub mod canary;
pub mod guard;
pub mod containers;
pub mod api;

pub use types::{SanitizationLevel, StackCanaryConfig, SanitizationStats};
pub use erase::{secure_zero, secure_zero_slice, dod_5220_erase, paranoid_erase, gutmann_erase, sanitize, sanitize_slice};
pub use canary::{init_stack_canary, get_stack_canary, verify_stack_canary, stack_canary_failed};
pub use guard::{GuardPage, allocate_with_guards, free_with_guards};
pub use containers::{SensitiveData, SecureString};
pub use api::{on_free, on_realloc, sanitize_process_memory, zerostate_shutdown_wipe, sanitization_stats, init, set_level, get_level};
