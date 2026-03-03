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

mod controller;
mod core;
mod msix;

pub use controller::{
    disable_legacy_interrupt, enable_legacy_interrupt, get_interrupt_line, get_interrupt_pin,
    MsiController,
};
pub use core::{
    configure_msi, configure_msi_multi, disable_msi, is_msi_enabled, mask_msi_vector,
    unmask_msi_vector,
};
pub use msix::{
    configure_msix, configure_msix_single, disable_msix, enable_msix, is_msix_enabled,
    is_msix_vector_pending, mask_all_msix, mask_msix_vector, unmask_all_msix, unmask_msix_vector,
};
