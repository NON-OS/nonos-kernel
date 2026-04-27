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

pub use super::super::tpm::{
    create_quote, extend_pcr_sha256, get_measurement_log, get_random_bytes as tpm_get_random_bytes,
    get_tpm_status, init_tpm, is_tpm_available, measure_component, measure_config_change,
    measure_module, read_pcr, shutdown_tpm, verify_boot_chain, BootChainMeasurements,
    ComponentType, PcrMeasurement, TpmError, TpmResult, TpmStatus,
};
pub use super::super::virtio_rng::{
    fill_random as virtio_rng_fill, get_random_bytes as virtio_rng_get_bytes, init_virtio_rng,
    is_available as virtio_rng_available,
};
