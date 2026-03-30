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

pub const PERCPU_BASE: u64 = 0xFFFF_FFC0_0000_0000;
pub const PERCPU_STRIDE: u64 = 0x0000_0100_0000;
pub const PERCPU_STACKS_BASE: u64 = 0xFFFF_FFD0_0000_0000;
pub const KSTACK_SIZE: usize = 64 * 1024;
pub const IST_STACK_SIZE: usize = 32 * 1024;
pub const GUARD_PAGES: usize = 1;
pub const IST_STACKS_PER_CPU: usize = 8;
