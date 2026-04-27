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

mod address;
mod align;
mod kaslr_ops;
mod percpu;
mod regions;
mod state;

pub use address::{in_kernel_space, in_user_space, is_canonical, range, selfref_l4_va};
pub use align::{align_down, align_up, is_aligned, is_page_aligned};
pub use kaslr_ops::{
    apply_kaslr_slide, get_layout, get_slide, heap_base_for, is_initialized, kernel_vaddr_to_phys,
    mmio_window, randomize_layout_from_kaslr, slid_address, slid_range, validate_layout, vm_window,
};
pub use percpu::{
    get_all_stack_regions, get_module_regions, get_percpu_region_for, get_percpu_regions,
};
pub use regions::{layout_summary, log_kernel_sections, managed_span, region_from_firmware};
pub use state::{
    boot_stacks_region, kernel_end, kernel_sections, kernel_start, percpu_template_region,
};
