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

mod state;
mod align;
mod address;
mod kaslr_ops;
mod regions;
mod percpu;

pub use align::{align_down, align_up, is_aligned, is_page_aligned};
pub use address::{in_kernel_space, in_user_space, is_canonical, range, selfref_l4_va};
pub use state::{kernel_sections, kernel_start, kernel_end, boot_stacks_region, percpu_template_region};
pub use kaslr_ops::{apply_kaslr_slide, get_slide, get_layout, is_initialized, slid_address, slid_range, validate_layout, kernel_vaddr_to_phys, heap_base_for, vm_window, mmio_window, randomize_layout_from_kaslr};
pub use regions::{region_from_firmware, managed_span, log_kernel_sections, layout_summary};
pub use percpu::{get_all_stack_regions, get_percpu_regions, get_percpu_region_for, get_module_regions};
