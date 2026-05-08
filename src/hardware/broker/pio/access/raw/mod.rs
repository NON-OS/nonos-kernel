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

//! Architectural `in`/`out` instructions, one width per file.
//! These are the only callers of `core::arch::asm!("in"/"out")`
//! in the kernel; everything else funnels through the broker
//! grant lookup before reaching them.

pub(super) mod in16;
pub(super) mod in32;
pub(super) mod in8;
pub(super) mod out16;
pub(super) mod out32;
pub(super) mod out8;
