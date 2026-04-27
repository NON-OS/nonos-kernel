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

use super::super::types::KernelMeasurement;
use super::types::AttestationManager;
use crate::zk_engine::ZKError;

pub(super) fn measure_kernel_state(mgr: &AttestationManager) -> Result<KernelMeasurement, ZKError> {
    let mut measurement = KernelMeasurement::new();
    measurement.code_hash = super::hash_code::hash_kernel_code(mgr)?;
    measurement.data_hash = super::hash_data::hash_kernel_data(mgr)?;
    measurement.memory_layout = super::memory::measure_memory_layout(mgr)?;
    measurement.module_hashes = super::hash_modules::hash_loaded_modules(mgr)?;
    measurement.config_hash = super::hash_modules::hash_kernel_config(mgr)?;
    measurement.integrity_hash = measurement.compute_integrity_hash();
    Ok(measurement)
}
