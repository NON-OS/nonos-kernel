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

pub mod state;
pub mod rsdp;
pub mod root;
pub mod fadt;
pub mod madt;
pub mod other;
pub mod getters;
pub mod init;

pub use state::is_initialized;
pub use init::init;
pub use getters::{
    revision, oem_id, lapic_address, has_legacy_pics, processors, ioapics,
    interrupt_overrides, nmi_configs, numa_regions, pcie_segments, hpet_address,
    pm_profile, sci_interrupt, stats, has_table, table_address, with_data,
};
