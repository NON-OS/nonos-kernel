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
mod init;
mod mapping;
mod query;
mod protection;
mod address_space;
mod faults;
mod tlb_ops;
mod stats;

pub use init::{init, is_initialized};
pub use mapping::{map_page, map_huge_page, unmap_page, map_kernel_page, map_user_page, map_device_memory};
pub use query::{translate_address, is_mapped, get_mapping_info, get_page_permissions};
pub use protection::{update_page_flags, update_page_protection, protect_pages, protect_pages_range};
pub use address_space::{create_address_space, switch_address_space, cleanup_address_space, lookup_asid_for_process, switch_to_process_address_space};
pub use faults::handle_page_fault;
pub use tlb_ops::{flush_tlb, invalidate_page, invalidate_all_pages, get_current_cr3, set_cr3, enable_write_protection, disable_write_protection};
pub use stats::{get_paging_stats, get_memory_usage};
