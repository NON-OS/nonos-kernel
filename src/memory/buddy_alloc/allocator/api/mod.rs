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
mod mapping;
mod stats;

pub use alloc::{allocate_aligned, allocate_pages};
pub use dealloc::{deallocate_aligned, deallocate_pages, free_aligned, free_pages};
pub use stats::{get_allocation_size, get_allocation_stats, init, is_valid_allocation};
pub use stats::{peak_allocated, total_allocated, validate_range};
