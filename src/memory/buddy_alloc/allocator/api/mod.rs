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

mod alloc;
mod dealloc;
mod stats;
mod mapping;

pub use alloc::{allocate_pages, allocate_aligned};
pub use dealloc::{free_pages, free_aligned, deallocate_pages, deallocate_aligned};
pub use stats::{init, get_allocation_stats, is_valid_allocation, get_allocation_size};
pub use stats::{validate_range, total_allocated, peak_allocated};
