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

mod types;
mod translate;
mod init;
mod mapping;
mod query;
mod secure;
mod stats;
mod tlb;
mod system;
mod system_stats;

pub use types::{MemoryProtection, MemoryType};
pub use translate::{phys_to_virt, virt_to_phys};
pub use init::init_unified_vm;
pub use mapping::{map_memory, unmap_memory};
pub use query::{translate_virtual, is_address_mapped, handle_unified_page_fault};
pub use secure::{allocate_secure_region, validate_access};
pub use stats::{UnifiedVmStats, get_unified_vm_stats};
pub use tlb::{flush_tlb_range, flush_tlb_all};
pub use system::{init_all_memory_subsystems, verify_all_memory_integrity};
pub use system_stats::{MemorySystemStats, get_memory_system_stats};
