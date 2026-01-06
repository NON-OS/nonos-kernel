// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const CANARY_BASE: u64 = 0xDEADBEEFCAFEBABE;
pub const ACCESS_HISTORY_MAX: usize = 1000;
pub const OVERFLOW_DETECTION_WINDOW: usize = 10;
pub const SEQUENTIAL_WRITE_THRESHOLD: usize = 5;
pub const SEQUENTIAL_WRITE_GAP: u64 = 64;
pub const UAF_DETECTION_WINDOW: usize = 50;
pub const UAF_TIME_THRESHOLD: u64 = 1_000_000;
pub const CANARY_MIX_CONSTANT: u64 = 0x9e3779b97f4a7c15;
pub const VGA_BUFFER_START: u64 = 0xB8000;
pub const VGA_BUFFER_END: u64 = 0xB8FA0;
