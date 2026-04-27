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

pub mod asm;
pub mod calibration;
pub mod constants;
mod conversion;
pub mod cpuid_ops;
mod deadline;
mod delay;
mod elapsed;
mod error;
mod features;
pub mod globals;
mod init_state;
pub mod io;
mod per_cpu;
mod rdtsc;
pub mod state;
mod stats_query;
pub mod types;

pub use asm::{rdtsc, rdtsc_unserialized, rdtscp, read_tsc, read_tsc_cpu, tsc_fence};
pub use calibration::cpuid::get_cpuid_frequency;
pub use calibration::hpet::calibrate_with_hpet;
pub use calibration::pit::calibrate_with_pit;
pub use calibration::{
    calibrate, calibrate_with_hpet_base, get_frequency, get_frequency_mhz, set_frequency,
};
pub use constants::{
    CALIBRATION_SAMPLES, DEFAULT_CALIBRATION_MS, MAX_CPUS, MAX_FREQUENCY, MIN_FREQUENCY,
};
pub use conversion::{
    ms_to_ticks, ns_to_ticks, ns_to_tsc, ticks_to_ms, ticks_to_ns, ticks_to_us, tsc_to_ns,
    us_to_ticks,
};
pub use cpuid_ops::{cpuid, cpuid_max_extended_leaf, cpuid_max_leaf};
pub use deadline::{clear_deadline, read_deadline, set_deadline_ns, write_deadline};
pub use delay::{delay_ms, delay_ns, delay_precise_ns, delay_us};
pub use elapsed::{elapsed_ms, elapsed_ns, elapsed_secs, elapsed_us};
pub use error::{TscError, TscResult};
pub use features::{
    detect_features, get_features, has_deadline_mode, has_rdtscp, is_invariant, is_tsc_available,
};
pub use globals::{
    CALIBRATED, CALIBRATION, FEATURES, INITIALIZED, PER_CPU_TSC, STATS_RDTSCP_CALLS,
    STATS_RDTSC_CALLS,
};
pub use io::{inb, outb};
pub use per_cpu::{get_cpu_offset, init_cpu, read_synchronized, sync_with_bsp};
pub use state::{
    get_calibration_source, get_confidence, get_statistics, init, init_with_hpet, is_calibrated,
    is_initialized,
};
pub use types::{CalibrationSource, PerCpuTsc, TscCalibration, TscFeatures, TscStatistics};
