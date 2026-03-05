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

//! Memory Safety Constants

/// Base value for canary generation.
pub const CANARY_BASE: u64 = 0xDEADBEEFCAFEBABE;

/// Maximum number of access patterns to track in history.
pub const ACCESS_HISTORY_MAX: usize = 1000;

/// Window size for buffer overflow pattern detection.
pub const OVERFLOW_DETECTION_WINDOW: usize = 10;

/// Threshold for sequential writes indicating potential overflow.
pub const SEQUENTIAL_WRITE_THRESHOLD: usize = 5;

/// Maximum address gap for sequential write detection.
pub const SEQUENTIAL_WRITE_GAP: u64 = 64;

/// Window size for use-after-free pattern detection.
pub const UAF_DETECTION_WINDOW: usize = 50;

/// Time threshold (in TSC ticks) for use-after-free detection.
pub const UAF_TIME_THRESHOLD: u64 = 1_000_000;

/// Constant for canary mixing.
pub const CANARY_MIX_CONSTANT: u64 = 0x9e3779b97f4a7c15;

/// VGA buffer start address.
pub const VGA_BUFFER_START: u64 = 0xB8000;

/// VGA buffer end address.
pub const VGA_BUFFER_END: u64 = 0xB8FA0;
