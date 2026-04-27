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
mod api;
mod api_alloc;
mod dealloc;
mod helpers;
mod memops;
mod state;
mod stats_api;
mod stats_internal;
mod validate;

pub use api::{
    allocate_memory, deallocate_memory, get_region_info, init, is_initialized, is_valid_address,
    validate_memory_access,
};
pub use api_alloc::{
    allocate_code_region, allocate_data_region, allocate_device_region, allocate_heap_region,
    allocate_secure_capsule, allocate_stack_region,
};
pub use memops::{copy_memory, zero_memory};
pub use stats_api::{
    get_allocation_count, get_deallocation_count, get_memory_stats, get_peak_memory,
    get_region_count, get_total_memory,
};
