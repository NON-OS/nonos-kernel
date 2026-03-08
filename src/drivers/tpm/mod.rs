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

extern crate alloc;

mod api;
mod constants;
mod driver;
mod error;
mod measurement;
mod mmio;
mod status;

#[cfg(test)]
#[cfg(not(feature = "std"))]
mod tests;

pub use api::{
    create_quote, extend_pcr_sha256, get_random_bytes, get_tpm_status, init_tpm,
    is_tpm_available, measure_component, measure_config_change, measure_module, read_pcr,
    shutdown_tpm, verify_boot_chain,
};
pub use constants::*;
pub use error::{TpmError, TpmResult};
pub use measurement::{
    clear_measurement_log, get_measurement_log, BootChainMeasurements, ComponentType, PcrMeasurement,
};
pub use status::{PcrBankConfig, TpmStatus};
