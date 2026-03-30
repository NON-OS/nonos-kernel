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

mod stats_internal;
mod state;
mod alloc;
mod dealloc;
mod validate;
mod helpers;
mod stats_api;
mod api;
mod api_alloc;
mod memops;

pub use api::{
    init, allocate_memory, deallocate_memory, get_region_info,
    validate_memory_access, is_valid_address, is_initialized,
};
pub use api_alloc::{
    allocate_code_region, allocate_data_region, allocate_heap_region,
    allocate_stack_region, allocate_secure_capsule, allocate_device_region,
};
pub use memops::{zero_memory, copy_memory};
pub use stats_api::{
    get_memory_stats, get_total_memory, get_peak_memory,
    get_allocation_count, get_deallocation_count, get_region_count,
};
