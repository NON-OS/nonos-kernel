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

mod globals;
mod allocator;
mod alloc;
mod dealloc;
mod mapping;
mod stats;
mod api;

pub use api::{init, allocate_page, allocate_pages, allocate_sized, deallocate_page};
pub use api::{get_page_info, get_stats, is_allocated, get_allocation_count};
pub use api::{get_total_bytes_allocated, get_peak_pages, is_initialized};
