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

mod apply_cbit_to_kernel_mappings;
mod reload_cr3;
mod set_cbit_on_pte;
mod walk_pd;
mod walk_pdpt;
mod walk_pml4_entry;
mod walk_pt;

pub use apply_cbit_to_kernel_mappings::apply_cbit_to_kernel_mappings;
