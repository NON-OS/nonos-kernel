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

pub mod advanced;
mod api;
pub mod constants;
pub mod error;
pub mod hw;
pub mod manager;
pub mod stats;
pub mod types;

pub use api::{handlers, init, is_protection_enabled, monitor_smi, regions, stats, verify_integrity};
pub use constants::{
    amd_msr, cr4, intel_msr, smi_en, smramc, LEGACY_SMRAM_BASE, LEGACY_SMRAM_SIZE,
    SMI_EN_OFFSET, SMI_STS_OFFSET, SMRAMC_REGISTER, SMM_ENTRY_OFFSET, SMM_SAVE_STATE_32,
    SMM_SAVE_STATE_64,
};
pub use error::{SmmError, SmmResult};
pub use manager::{SmmManager, SMM_MANAGER};
pub use stats::SmmStats;
pub use types::{CpuVendor, SmiInfo, SmiSource, SmmHandler, SmmRegion, SmmRegionType};
