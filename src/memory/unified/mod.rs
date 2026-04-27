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

mod init;
mod mapping;
mod query;
mod secure;
mod stats;
mod system;
mod system_stats;
mod tlb;
mod translate;
mod types;

pub use init::init_unified_vm;
pub use mapping::{map_memory, unmap_memory};
pub use query::{handle_unified_page_fault, is_address_mapped, translate_virtual};
pub use secure::{allocate_secure_region, validate_access};
pub use stats::{get_unified_vm_stats, UnifiedVmStats};
pub use system::{init_all_memory_subsystems, verify_all_memory_integrity};
pub use system_stats::{get_memory_system_stats, MemorySystemStats};
pub use tlb::{flush_tlb_all, flush_tlb_range};
pub use translate::{phys_to_virt, virt_to_phys};
pub use types::{MemoryProtection, MemoryType};
