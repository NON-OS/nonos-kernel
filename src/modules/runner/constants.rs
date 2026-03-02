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

pub const RUNNER_VERSION: u16 = 1;
pub const MAX_CONCURRENT_MODULES: usize = 256;
pub const MODULE_STACK_SIZE: usize = 64 * 1024;
pub const MODULE_HEAP_SIZE: usize = 1024 * 1024;
pub const STARTUP_TIMEOUT_MS: u64 = 5000;
pub const SHUTDOWN_TIMEOUT_MS: u64 = 3000;
pub const FAULT_RETRY_COUNT: u32 = 3;
pub const FAULT_BACKOFF_MS: u64 = 100;
pub const HEARTBEAT_INTERVAL_MS: u64 = 1000;
pub const WATCHDOG_TIMEOUT_MS: u64 = 10000;
